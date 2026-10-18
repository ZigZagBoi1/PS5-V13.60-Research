# PS5 kernel dumper (13.60)

Build with the installed ps5-payload-dev SDK:

```sh
make PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
```

After Relapse and the HV stage report success, sideload with:

```sh
make PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk PS5_HOST=<PS5_IP> deploy
```

`main.c` obtains the text and data base constants from the SDK, reads the 13.60
sysent table at RVA `0xe6e5c0`, validates the first eight handler pointers, then
streams the 679 x 48-byte table and the first 4 KiB at each syscall handler
address from 532–676. Reads are limited to 4 KiB with 100 ms pauses. Each chunk
is sent as an HTTP POST to `http://10.0.0.231:8888/dump` with `X-Filename`,
`X-Chunk`, and `X-Offset` headers, so completed chunks can remain available if a
later read or send fails.

Run it only after Relapse and the 13.60 HV stage have completed. The dumper
does not write kernel memory. It stops on a read error, invalid initial sysent
sample, or rejected receiver response. This build covers sysent and the Sony
handler ranges; full text/data, ucred, and module-list extraction are not
included.

The deploy target sends the ELF to the PS5's elfldr on port 9021.

`ps5-full-kernel-dumper.elf` is a legacy, misleading target name. Its current
source, `full_dump.c`, does **not** enumerate modules with `kldnext`/`kldstat`
or discover complete section bounds. It reads three fixed ranges: `0xe6e5c0`
bytes from the configured kernel base, 4 MiB at base `+0x1000000`, and 64 KiB
around the sysent table. The first range crosses the `.text`/`.data` boundary;
the second is only a `.data` sample. The source checks the configured base
against the SDK base and emits a per-range `.failmap`, but this is not a full
kernel image dump. See the [capture coverage table](../docs/dumps_13.60/README.md) and [reconciliation audit](../docs/audits/2026-10-18-dump-reconciliation.md) for exact limits.

Both ELFs post to a dedicated HTTP receiver on `10.0.0.231:8888`. That
receiver's source and configuration are not included here. The audited research
web server on port 8875 is a separate service: its `/dump` endpoint accepts only
the session-bound `kernel_base.json` and `sysent_raw.bin` workflow, so it is not
a compatible receiver for these dumper requests. The external receiver must
validate filenames and offsets, handle retries idempotently, and be reachable
only on a trusted local network. No receiver integration or console run is
verified by the tests in this repository.

The checked-in `.elf` files are not proven to have been built from these exact
sources. Rebuild with the PS5 SDK and verify the receiver contract before any
deployment. The deploy target sends the ELF to the console's elfldr on port
9021; it does not validate a console session or receiver behavior.

Deploy the range-only build with:

```sh
make PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk PS5_HOST=<PS5_IP> deploy-full
```
