# PS5 13.60 HV integration

The site uses the upstream [Relapse-Exploit](https://github.com/ntfargo/Relapse-Exploit) and the upstream [Byepervisor-Reborn](https://github.com/PS5Dev/Byepervisor-Reborn) base payload.

Byepervisor-Reborn source commit: `ea04f7132b837087f552c57261cb800481a3a910`.

The locally built payload is `byepervisor_reborn.elf` (177,256 bytes; SHA-256 `0c43dcd8a6119726f7245b45bca6b5c227ad4b4aeeadb6fa3a22e3f82448533f`). The backend sends it over TCP to the requesting PS5's port 9021 only after an explicit confirmation. Browser User-Agent, Origin/Referer, host, and the observed LAN subnet gate both the status and send APIs. The webpage never retries a send automatically.

The console remains the source for success confirmation: transfer completion does not prove the HV bypass, and the user must follow the rest-mode and resume instructions. The upstream payload provides no HEN or other kernel patches.

Relapse integration note: the page loads the upstream scripts after the document body exists, waits for the firmware-specific offsets to finish loading, then starts the WebKit stage. The Relapse and HV pages automatically send page status, exploit log messages, and payload-transfer results to `/var/lib/ps5-research/relapse-diagnostics/`; pointer-shaped hexadecimal values are redacted, batches and total session lines are capped, and the endpoint accepts requests only from a PS5 user agent on the local `10.0.0.0/24` network. The HV page can also record the user's confirmation of the post-resume notification; it cannot inspect native notifications itself. The page layout scales down for the console browser and short viewports.
