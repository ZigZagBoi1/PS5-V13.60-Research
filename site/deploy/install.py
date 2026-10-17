"""Install only the PS5 service and its Nginx route; preserve backup for rollback."""
from datetime import datetime, timezone
import grp
import os
from pathlib import Path
import pwd
import shutil
import subprocess

ROOT = Path('/var/www/ps5-research')
CONFIG = Path('/etc/nginx/sites-enabled/default').resolve(strict=True)
SNIPPET = Path('/etc/nginx/snippets/ps5-research.conf')
UNIT = Path('/etc/systemd/system/ps5-research.service')

def command(*args):
    subprocess.run(args, check=True)

def main():
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo; deployment only touches the PS5 route/service')
    if CONFIG not in (Path('/etc/nginx/sites-available/default'), Path('/etc/nginx/sites-enabled/default')):
        raise SystemExit(f'Unexpected Nginx config target: {CONFIG}')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup = Path('/var/backups/ps5-research') / stamp
    backup.mkdir(parents=True, exist_ok=False)
    shutil.copy2(CONFIG, backup / 'nginx-default.conf')
    if SNIPPET.exists():
        shutil.copy2(SNIPPET, backup / 'ps5-research.conf')
    if UNIT.exists():
        shutil.copy2(UNIT, backup / 'ps5-research.service')
    text = CONFIG.read_text()
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
    shutil.copyfile(ROOT / 'deploy/ps5-research.conf', SNIPPET)
    shutil.copyfile(ROOT / 'deploy/ps5-research.service', UNIT)
    os.chmod(SNIPPET, 0o644)
    os.chmod(UNIT, 0o644)
    CONFIG.write_text(text)
    try:
        command('nginx', '-t')
        command('systemctl', 'daemon-reload')
        command('systemctl', 'enable', '--now', 'ps5-research.service')
        command('systemctl', 'restart', 'ps5-research.service')
        command('systemctl', 'is-active', '--quiet', 'ps5-research.service')
        command('systemctl', 'reload', 'nginx')
    except Exception:
        shutil.copy2(backup / 'nginx-default.conf', CONFIG)
        if (backup / 'ps5-research.conf').exists():
            shutil.copy2(backup / 'ps5-research.conf', SNIPPET)
        command('nginx', '-t')
        raise
    print('Installed /ps5/ and ps5-research.service. Backup:', backup)

if __name__ == '__main__':
    main()
