# PS5 V13.60 Research

Research notes and the locally hosted browser tooling for an owned PS5 running firmware 13.60. The folder keeps the Relapse stage, the Byepervisor-Reborn HV stage, captured research data, and deployment source together.

## Repository layout

- `site/web/` — editable website source.
- `site/release/` — deployment snapshot that is served by the local research server.
- `site/server/` and `site/release/server/` — bounded local site/API implementation.
- `upstream/Relapse-Exploit/` — upstream Relapse source, pinned as a submodule.
- `upstream/Byepervisor-Reborn/` — upstream Byepervisor-Reborn source, pinned as a submodule.
- `artifacts/` — locally built payload artifact used by the site.
- `docs/` — firmware-specific research data and notes.
- `HV-RELAPSE-13.60.md` — exploit order, requirements, source links, and observed stage evidence.

The `site/release/` files include integration changes and are not identical to the upstream projects. The top-level `site/HV-INTEGRATION.md` records their source commit and local integration details. Generated package archives and Python bytecode are excluded from version control.

## Current evidence

The 2026-10-17 PS5 browser diagnostics recorded Relapse completion and the ELF loader on port 9021. The server access log recorded an HTTP 200 for the Byepervisor payload transfer. That confirms delivery only; the server cannot inspect the native post-resume notification. The HV page now logs transfer results and can record a user-confirmed success notification separately.

## Related work

The V14.10 research project retains a compatibility copy of `docs/ps5_13.60_sysent.json` because its strategy and probe tooling read that path. The authoritative research copy is kept here; see `docs/RELATED_V14_10_RESEARCH.md` for attribution.

## Scope

This repository is for research on hardware the owner is authorized to test. Exploit stages can crash or destabilize the console. The upstream Byepervisor-Reborn project is a developer base and does not include HEN, debug patches, or a general homebrew setup.
