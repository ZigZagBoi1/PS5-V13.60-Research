"""Install only the PS5 service and its Nginx route; preserve backup for rollback."""
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path('/var/www/ps5-research')
CONFIG = Path('/etc/nginx/sites-enabled/default')
SNIPPET = Path('/etc/nginx/snippets/ps5-research.conf')
UNIT = Path('/etc/systemd/system/ps5-research.service')

def command(*args):
    subprocess.run(args, check=True)

def apply_configuration(config, snippet, unit, backup, text):
    """Restore all config files and the previous service state on failure."""
    previous = {}
    for path, name in ((config, 'nginx-default.conf'), (snippet, 'ps5-research.conf'), (unit, 'ps5-research.service')):
        previous[path] = backup / name if path.exists() else None
        if previous[path]:
            shutil.copy2(path, previous[path])
    was_active = subprocess.run(('systemctl', 'is-active', '--quiet', 'ps5-research.service'), check=False).returncode == 0
    was_enabled = subprocess.run(('systemctl', 'is-enabled', '--quiet', 'ps5-research.service'), check=False).returncode == 0
    try:
        shutil.copyfile(ROOT / 'deploy/ps5-research.conf', snippet)
        shutil.copyfile(ROOT / 'deploy/ps5-research.service', unit)
        os.chmod(snippet, 0o644)
        os.chmod(unit, 0o644)
        config.write_text(text)
        command('nginx', '-t')
        command('systemctl', 'daemon-reload')
        command('systemctl', 'enable', 'ps5-research.service')
        command('systemctl', 'restart', 'ps5-research.service')
        command('systemctl', 'is-active', '--quiet', 'ps5-research.service')
        command('systemctl', 'reload', 'nginx')
    except Exception as error:
        for path, saved in previous.items():
            if saved:
                shutil.copy2(saved, path)
            else:
                path.unlink(missing_ok=True)
        rollback = [('systemctl', 'daemon-reload')]
        rollback.append(('systemctl', 'restart' if was_active else 'stop', 'ps5-research.service'))
        if not was_enabled:
            rollback.append(('systemctl', 'disable', 'ps5-research.service'))
        rollback.extend((('nginx', '-t'), ('systemctl', 'reload', 'nginx')))
        for args in rollback:
            try:
                command(*args)
            except Exception as rollback_error:
                print(f'Rollback command {args!r} also failed: {rollback_error}')
        raise

def main():
    import grp
    import pwd
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo; deployment only touches the PS5 route/service')
    config = CONFIG.resolve(strict=True)
    if config not in (Path('/etc/nginx/sites-available/default'), Path('/etc/nginx/sites-enabled/default')):
        raise SystemExit(f'Unexpected Nginx config target: {config}')
    # Validate the composed release before changing live configuration.
    import hashlib
    import json
    manifest = json.loads((ROOT / 'release-manifest.json').read_text(encoding='utf-8'))
    if manifest.get('firmware') != '13.60' or manifest.get('hv_sha256') != '0c43dcd8a6119726f7245b45bca6b5c227ad4b4aeeadb6fa3a22e3f82448533f':
        raise SystemExit('Unexpected release manifest')
    for relative, expected in manifest['files'].items():
        path = (ROOT / relative).resolve(strict=True)
        if ROOT.resolve() not in path.parents or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit(f'Release integrity check failed: {relative}')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup = Path('/var/backups/ps5-research') / stamp
    backup.mkdir(parents=True, exist_ok=False)
    text = config.read_text()
    include = '    include /etc/nginx/snippets/ps5-research.conf;'
    if include not in text:
        marker = '    # --- A. MAIN PORTFOLIO (Root) ---'
        if text.count(marker) != 1:
            raise SystemExit('Expected exactly one portfolio HTTPS marker; configuration unchanged')
        text = text.replace(marker, include + '\n\n' + marker, 1)
    for path in (ROOT, ROOT / 'server', ROOT / 'web', ROOT / 'experiments', ROOT / 'dashboard', ROOT / 'deploy'):
        os.chmod(path, 0o755)
        for file in path.iterdir():
            if file.is_file() and file.suffix != '.key':
                os.chmod(file, 0o644)
    private = ROOT / 'private'
    os.chmod(private, 0o750)
    os.chown(private, 0, grp.getgrnam('www-data').gr_gid)
    key = private / 'dashboard.key'
    os.chmod(key, 0o600)
    os.chown(key, pwd.getpwnam('www-data').pw_uid, grp.getgrnam('www-data').gr_gid)
    hv_directory = private / 'hv'
    os.chmod(hv_directory, 0o750)
    os.chown(hv_directory, 0, grp.getgrnam('www-data').gr_gid)
    hv_payload = hv_directory / 'byepervisor_reborn.elf'
    os.chmod(hv_payload, 0o640)
    os.chown(hv_payload, 0, grp.getgrnam('www-data').gr_gid)
    apply_configuration(config, SNIPPET, UNIT, backup, text)
    print('Installed /ps5/ and ps5-research.service. Backup:', backup)

if __name__ == '__main__':
    main()
