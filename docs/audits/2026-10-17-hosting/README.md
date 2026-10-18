# PS5 13.60 hosting audit

## Scope and observed deployment

Audited the static Relapse and Byepervisor pages, payload delivery service, deployment configuration, and release workflow for `https://marwanmohamed.ca/ps5/`. Live page and asset hashes matched the checked-in release artifacts during the audit. The upstream Relapse ELF loader and kernel payload matched their pinned upstream files; the Byepervisor artifact matched pinned upstream commit `ea04f7132b837087f552c57261cb800481a3a910` and its expected SHA-256.

Live hashes and response sizes are recorded in [live-inventory.json](live-inventory.json). Raw GET snapshots are in the ignored `live/` directory. The `/api/health` response is dynamic and is not expected to match a static release file.

## Main finding: split the boot flow into two ordered stages

Relapse and Byepervisor are separate stages in one console boot. Relapse starts the kernel exploit and ELF loader; after Relapse has completed its cleanup, the user continues to the separate HV page, which sends Byepervisor to that same console. They must not be launched at the same time, and a loader-start message alone does not establish that Relapse cleanup completed.

The live version did not enforce this boundary: its Relapse page could pause for manual dump controls before cleanup, while the HV page had no server-verified indication that cleanup had finished. That left a window where the HV send could be attempted while Relapse workers and kernel objects were still active. This is a plausible explanation for a console hanging while entering Rest Mode, but it is not proven to be the cause. The user recalls a pulsing white LED before the console reached orange Rest Mode, but not the final on-screen Relapse message. No console-side execution or power test was performed during this audit.

The local audited version now has a compact start page with separate Relapse and HV page choices. The Relapse page no longer offers a same-boot Continue-to-HV action. The HV page states its current limitation instead of implying that it starts an exploit by itself.

The split is currently a navigation and safety improvement, not two fully independent exploit implementations: the HV page only sends an ELF to an already-running loader, and the server still requires a recorded Relapse session before it permits that send. A standalone HV path needs a separate compatible loader/exploit entry point and has not been implemented. The current HV sender retains its one-send lock for ambiguous or failed delivery.

Manual extraction is opt-in at `?mode=dump`; that session pauses for **Finish & restore** and is kept out of the normal HV flow. A dump receiver must be configured separately.

## Other findings

- The HV page previously allowed a send retry after some HTTP errors, even when the server might have already started a transfer. The local audited version treats an ambiguous transfer as uncertain and blocks a second send for that session.
- Payload size, hash, and source-version checks are now part of the local send path. The server records the console IP associated with diagnostic readiness and the HV confirmation.
- The installer now restores the prior Nginx files and systemd unit state if installation fails. Release packaging verifies hashes before producing a deterministic archive and excludes the local dashboard key.
- The server's SSH login was not available to the audit account, so server journal logs and its current service configuration were not inspected. No credentials were guessed or retried.

## Status

The revised pages and hosting checks are local changes only. The live deployment still matches the pre-audit release and has not been changed. The archive `site/hv-site-package-audited-20261017.tar.gz` is a complete locally built deployment package, not an installation. Build and verify it with:

```powershell
python site/build_release.py
python site/build_release.py --check --package site/hv-site-package-audited-20261017.tar.gz
```

Regression coverage uses mocked console sockets. It checks sequential readiness, retry locks, payload integrity, diagnostics, and rollback behavior without contacting a PS5 or sending an exploit payload.
