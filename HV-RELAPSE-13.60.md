# Relapse and hypervisor stage on PS5 firmware 13.60

Checked 2026-10-17 against the upstream project READMEs and the local PS5 research server.

## Findings

- Relapse is the kernel stage for firmware 7.00–13.60. Its README says a successful run leaves default payloads available and an ELF loader listening on TCP port 9021. WebKit may need retries; a hang or kernel panic calls for a reboot before another attempt. Source: [ntfargo/Relapse-Exploit](https://github.com/ntfargo/Relapse-Exploit).
- The correct HV project for 13.60 is [PS5Dev/Byepervisor-Reborn](https://github.com/PS5Dev/Byepervisor-Reborn), not the original Byepervisor repository, whose README says it only supports 1.xx–2.xx. Reborn lists 13.60 and 13.20 as fully supported, with 13.00 untested; its README describes the current repository as a developer base rather than a ready-to-use homebrew solution.
- Reborn requires the kernel exploit and ELF loader first. Send `byepervisor.elf`, follow the console notifications, enter Rest Mode when prompted, then wake the console. Its notes say the payload relies on the loader remaining available through resume; set “Supply Power to USB Ports” to “Always” if required by the console setup. A shutdown during resume indicates failure.
- The reported HV result is a hypervisor bypass that allows access to HV memory and leaves kernel text readable/writable after resume. It does not include HEN, debug settings, or other kernel patches. Payload transfer alone is not success; the console's post-resume success notification is the confirmation.

## Observed on this PS5

The latest browser diagnostics identify firmware 13.60 and record `kernel exploit complete` followed by `elfldr is listening on port 9021`. The web server access log then records a successful `POST /ps5/api/hv/send` (HTTP 200) from the same PS5 session; the server implementation reports that this means the ELF was transferred to port 9021 and explicitly leaves `hv_confirmed` false.

This independently confirms the Relapse stage and delivery of the Byepervisor payload. The server does not receive the console's notification after Rest Mode/resume, so the final HV success state is not independently verifiable from server logs alone.

The HV page now sends status and transfer results to the same bounded, pointer-redacting diagnostics endpoint as the Relapse page. It also offers a checkbox to report the post-resume success notification; that record is explicitly a user report because the browser cannot read native PS5 notifications.

## Order of operations

1. Confirm the console remains on firmware 13.60 and open the local research site on that PS5.
2. Run Relapse and wait for `kernel exploit complete` and `elfldr is listening on port 9021`.
3. Open the HV stage on the same PS5, confirm the loader-ready prompt, and send the payload once.
4. Follow the console notification through Rest Mode and resume. Treat the post-resume success notification as the HV completion check.

## Sources

- [Relapse README](https://github.com/ntfargo/Relapse-Exploit/blob/main/README.md)
- [Byepervisor-Reborn README](https://github.com/PS5Dev/Byepervisor-Reborn)
- [Original Byepervisor README](https://github.com/PS5Dev/Byepervisor)
