"""Compose the pinned upstream release with editable hosting overrides.

No server connection or console payload delivery is performed by this script.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

SITE = Path(__file__).resolve().parent
REPO = SITE.parent
RELAPSE_COMMIT = 'dd8e4e0914c5e9d066ee1f9b056be76cb992c8e0'
HV_COMMIT = 'ea04f7132b837087f552c57261cb800481a3a910'
HV_SHA256 = '0c43dcd8a6119726f7245b45bca6b5c227ad4b4aeeadb6fa3a22e3f82448533f'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_upstream(path, commit):
    head = subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output(['git', '-C', str(path), 'status', '--porcelain', '--untracked-files=all'], text=True).strip()
    if head != commit or dirty:
        raise ValueError(f'Expected clean pinned upstream {path.name} at {commit}')


def files(root):
    return {p.relative_to(root).as_posix(): p for p in root.rglob('*')
            if p.is_file() and '__pycache__' not in p.parts}


def compose(destination):
    relapse = REPO / 'upstream' / 'Relapse-Exploit'
    verify_upstream(relapse, RELAPSE_COMMIT)
    verify_upstream(REPO / 'upstream' / 'Byepervisor-Reborn', HV_COMMIT)
    artifact = REPO / 'artifacts' / 'byepervisor_reborn-13.60.elf'
    if digest(artifact) != HV_SHA256:
        raise ValueError('The HV artifact does not match the audited 13.60 build')
    ignore = shutil.ignore_patterns('__pycache__', '*.pyc', '*.key')
    for part in ('src', 'offsets', 'payloads'):
        shutil.copytree(relapse / part, destination / 'web' / 'relapse' / part, ignore=ignore)
    for name in ('README.md', 'LICENSE'):
        shutil.copy2(relapse / name, destination / 'web' / 'relapse' / name)
    for part in ('server', 'web', 'experiments', 'dashboard', 'deploy'):
        shutil.copytree(SITE / part, destination / part, dirs_exist_ok=True, ignore=ignore)
    shutil.copy2(SITE / 'HV-INTEGRATION.md', destination / 'HV-INTEGRATION.md')
    private = destination / 'private' / 'hv'
    private.mkdir(parents=True)
    shutil.copy2(artifact, private / 'byepervisor_reborn.elf')
    manifest = {'schema': 1, 'firmware': '13.60', 'relapse_commit': RELAPSE_COMMIT,
                'hv_commit': HV_COMMIT, 'hv_sha256': HV_SHA256,
                'files': {name: digest(path) for name, path in sorted(files(destination).items())}}
    (destination / 'release-manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def package(root, output):
    output.parent.mkdir(parents=True, exist_ok=True)
    # Fixed ordering and metadata make repeated archives byte-identical.
    with output.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as archive:
            for name, path in sorted(files(root).items()):
                data = path.read_bytes()
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), 0o644, 0
                archive.addfile(info, io.BytesIO(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Verify the current release without writing it')
    parser.add_argument('--package', type=Path, help='Write a complete deployment archive without dashboard credentials')
    args = parser.parse_args()
    release = SITE / 'release'
    # The temporary directory and its automatic cleanup stay inside this site.
    with tempfile.TemporaryDirectory(prefix='.release-build-', dir=SITE) as temporary:
        staging = Path(temporary).resolve() / 'release'
        if staging.parent.parent != SITE.resolve():
            raise ValueError('Unexpected staging directory')
        staging.mkdir()
        compose(staging)
        expected = files(staging)
        existing = files(release)
        # A machine-local dashboard key may exist, but is never packaged.
        extras = set(existing) - set(expected) - {'private/dashboard.key'}
        if extras:
            raise ValueError('Unmanaged release files must be preserved explicitly before rebuilding: ' + ', '.join(sorted(extras)))
        mismatches = [name for name, path in expected.items()
                      if name not in existing or digest(path) != digest(existing[name])]
        if args.check and mismatches:
            raise ValueError('Release differs from editable sources: ' + ', '.join(mismatches))
        if not args.check:
            shutil.copytree(staging, release, dirs_exist_ok=True)
        if args.package:
            output = args.package.resolve()
            if output.parent != SITE.resolve() or output.suffixes[-2:] != ['.tar', '.gz']:
                raise ValueError('Deployment archive must be a .tar.gz directly inside site/')
            package(staging, output)
            print(f'Package: {output} (sha256={digest(output)})')
        print(f'Verified {len(expected)} release files against pinned upstreams and editable overrides.')


if __name__ == '__main__':
    main()
