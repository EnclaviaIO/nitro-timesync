# nitro-timesync

Keeps an AWS Nitro Enclave's wall clock (`CLOCK_REALTIME`) on the Nitro
hypervisor's time, using the `timestamp` of fresh attestation documents
from the enclave's own `/dev/nsm`. It is a single static binary with no
network access and no configuration files.

> **Status:** early. The offset math, decision logic and CLI are unit-tested;
> kernel support was checked against kernel sources and configs. Run it on
> your own enclaves and watch the logs before relying on it.

## The problem

A Nitro Enclave has no network, no NTP and no RTC it can trust. Its clock
is initialised at boot and then runs freely, so it drifts. Long-running
enclaves have been measured drifting by roughly **0.5 to 0.9 seconds per
day**, which adds up to tens of seconds over a few weeks.

Anything inside the enclave that reads the wall clock suffers:

* TLS certificate `notBefore` / `notAfter` checks, and DNSSEC signature
  validity windows;
* JWT `exp` / `nbf` / `iat` checks, signed timestamps, token expiry;
* log timestamps that no longer line up with the rest of your fleet;
* any "has enough time passed" logic based on wall-clock time.

## Why the NSM timestamp can be trusted

Every attestation document returned by the Nitro Secure Module carries a
`timestamp` field: milliseconds since the Unix epoch, written by the
**Nitro hypervisor** when it produces the document. The parent EC2
instance, which controls everything else the enclave talks to (vsock
traffic, the enclave image, when the enclave is started), has no way to
set or alter that field.

`nitro-timesync` asks the enclave's own `/dev/nsm` for a document and reads
the timestamp. It does **not** verify the COSE signature or the certificate
chain: the document comes straight from the local device, which is served
by the hypervisor, so there is no party in the path to authenticate
against. Verification only matters for a document that has travelled
through something untrusted, and this one has not.

The trust you place in this time source is the trust you already place in
the Nitro hypervisor for attestation.

## How it works

Each **round**:

1. Take 3 samples. For each, read `CLOCK_REALTIME`, request an attestation
   document (no nonce, user data or public key), read `CLOCK_REALTIME`
   again, and decode the document's `timestamp`.
2. Keep the sample with the **shortest round trip**. The offset is the NSM
   time minus the local midpoint of the request; the true offset is within
   half the round trip (plus half the timestamp resolution) of that.
3. Discard implausible samples: a round trip over 1 s, the local clock
   going backwards during the request, or a timestamp that is zero, before
   2026-01-01, or after 2100.
4. Decide, using the offset *minus* its uncertainty, so a slow request can
   never trigger a step by itself:
   * **first round (boot):** step if the offset is above **100 ms**;
   * **later rounds:** step if it is above **500 ms** (the kernel PLL's
     maximum phase correction, `MAXPHASE`, beyond which a slew would be
     clamped anyway);
   * otherwise **slew**.

Rounds repeat every **60 s**. On failure (NSM error, `adjtimex` error) the
round is retried with exponential backoff from 1 s up to 5 minutes. Once
running, the daemon does not exit on its own.

**Stepping** uses `adjtimex(ADJ_SETOFFSET)`, which adds the offset
atomically inside the kernel (no read-modify-write race as with
`clock_settime`).

**Slewing** feeds the offset to the kernel's NTP phase-locked loop
(`adjtimex` with `ADJ_OFFSET | ADJ_STATUS | ADJ_TIMECONST | ADJ_NANO` and
`STA_PLL`), with a time constant matched to the poll interval (6 for 60 s,
as ntpd uses for a 64 s poll). The PLL corrects the phase gradually **and
learns the frequency error**, so once it has converged the drift between
samples is close to zero. A plain `adjtime`-style slew
(`ADJ_OFFSET_SINGLESHOT`) would correct the phase but never the rate.

`STA_UNSYNC` is deliberately left set. While it is clear, kernels built
with `GENERIC_CMOS_UPDATE` or `RTC_SYSTOHC` write the system time to the
hardware RTC every 11 minutes, which is pointless in an enclave. It does
not affect the PLL.

Steps and slews only affect `CLOCK_REALTIME`. `CLOCK_MONOTONIC` never jumps
(it does run at the PLL-corrected rate, which is the point). Timers built
on monotonic time, such as `tokio::time`, `std::time::Instant` and
`CLOCK_MONOTONIC` timerfds, are not disturbed by a step. Code that measures
intervals with the wall clock (`SystemTime`, `gettimeofday`) will see a
step, which is why steps are reserved for boot and for large errors.

### Start-up modes

* **Default (daemon):** the process forks. The parent waits for the
  child's first round, up to `--boot-wait-ms` (5 s by default), then exits
  0 whatever happened. The child keeps running in its own session. Call it
  from your init script before starting anything that reads the clock:
  the rest of boot sees a corrected clock and is never blocked for long.
* **`--foreground`:** the same, without forking (for supervisors that
  expect a foreground process).
* **`--oneshot`:** one round in the foreground, step only (the PLL is not
  touched), then exit. Exits 0 after a successful round (stepped or not)
  and 1 if no usable sample could be taken or the kernel refused the step.

If `/dev/nsm` does not exist the binary logs one line and exits 0 in every
mode, so it is safe to include in images that also boot outside Nitro.

### QEMU's emulated NSM

QEMU's `nitro-enclave` machine emulates the NSM. Its documents carry
`timestamp = time(NULL) * 1000` (the **QEMU host's** clock, in whole
seconds) and an all-zero signing certificate. `nitro-timesync` detects the
all-zero certificate, treats the timestamp as having one-second
resolution, never slews, and only steps when the offset is certainly above
2 s. That keeps debug enclaves roughly on the host's time without chasing
quantisation noise. The emulated timestamp comes from the host, so none of
the guarantees above apply.

## Configuration

Every option can be given as a flag or as an environment variable; flags
win over the environment.

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--oneshot` | `NITRO_TIMESYNC_ONESHOT=1` | off | one step-only round, then exit |
| `--foreground` | `NITRO_TIMESYNC_FOREGROUND=1` | off | do not fork |
| `--no-slew` | `NITRO_TIMESYNC_NO_SLEW=1` | off | never drive the PLL; only step |
| `--interval-secs N` | `NITRO_TIMESYNC_INTERVAL_SECS` | 60 | seconds between rounds |
| `--samples N` | `NITRO_TIMESYNC_SAMPLES` | 3 | requests per round (1-16) |
| `--max-rtt-ms N` | `NITRO_TIMESYNC_MAX_RTT_MS` | 1000 | discard slower samples |
| `--boot-step-threshold-ms N` | `NITRO_TIMESYNC_BOOT_STEP_THRESHOLD_MS` | 100 | first-round step threshold |
| `--step-threshold-ms N` | `NITRO_TIMESYNC_STEP_THRESHOLD_MS` | 500 | later step threshold |
| `--boot-wait-ms N` | `NITRO_TIMESYNC_BOOT_WAIT_MS` | 5000 | how long the forking parent waits |
| `--log-level FILTER` | `NITRO_TIMESYNC_LOG_LEVEL` | `info` | [`tracing` filter][filter]; `RUST_LOG` is honoured too |

Boolean variables accept `1/true/yes/on` and `0/false/no/off`. Flags also
accept the `--name=value` form, e.g. `--oneshot=false`.

Logs go to stderr without ANSI colours. Every step is logged at `info`, as
are slews of 50 ms or more and an hourly summary; the rest is at `debug`.

[filter]: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html

## Adding it to an enclave image

The binary needs:

* to run as **root**, or with `CAP_SYS_TIME` (the stock Nitro init runs the
  entrypoint as root);
* **`/dev/nsm`**: the NSM driver (in-tree since Linux 6.8, `CONFIG_NSM`;
  the older kernel shipped with `nitro-cli` loads `nsm.ko`) and a mounted
  `devtmpfs`.

Use the **static** build: `nix build .#nitro-timesync-static` (also the
flake's `default` package), or
`cargo build --release --target x86_64-unknown-linux-musl`.

### With `nitro-cli build-enclave` (Dockerfile)

```dockerfile
FROM alpine:3
COPY nitro-timesync /usr/local/bin/nitro-timesync
COPY app /usr/local/bin/app
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

```sh
#!/bin/sh
# Returns after the first correction (at most 5 s); the daemon keeps
# running. Never let it block or fail the boot.
/usr/local/bin/nitro-timesync || echo "nitro-timesync failed" >&2
exec /usr/local/bin/app
```

### With Nix

```nix
inputs.nitro-timesync.url = "github:OWNER/nitro-timesync/<rev>";

# ...then copy it into the image's root filesystem:
cp ${nitro-timesync.packages.${system}.default}/bin/nitro-timesync $out/bin/
```

Adding the binary changes the image, and therefore its PCR0 and PCR2
measurements.

### Supervision

Nothing should depend on the daemon. If it fails, the clock simply drifts
as it would without it. As long as your PID 1 reaps orphaned processes
(the stock Nitro init does), the forked daemon needs no further
supervision.

## Kernel requirements

Everything used is part of the kernel's always-built timekeeping code:

* `adjtimex(2)` with the NTP PLL (`kernel/time/ntp.c` is built
  unconditionally; `CONFIG_NTP_PPS` is **not** needed);
* `ADJ_SETOFFSET` (Linux 2.6.39 and later);
* `CLOCK_REALTIME` / `CLOCK_MONOTONIC`.

Checked against the configuration of the AWS `nitro-cli` enclave kernel
(4.14) and the source and configuration of a minimal `allnoconfig`-based
7.1 enclave kernel. Both build the NTP code, and both set
`GENERIC_CMOS_UPDATE=y` (hence `STA_UNSYNC`, above).

## Security notes

* **What it trusts:** only the local NSM device, i.e. the Nitro
  hypervisor. It opens no sockets and reads no files besides `/dev/nsm`.
* **What it does not protect against:** anything inside the enclave with
  `CAP_SYS_TIME` can still set the clock. The daemon corrects such a change
  at its next round, but it is not a defence.
* **Accuracy:** bounded by half the attestation round trip plus 0.5 ms of
  timestamp quantisation, assuming the hypervisor's clock is right.
* **Keep the local clock out of security decisions where you can.** For
  example, verifying an attestation document at its own signed `timestamp`
  does not depend on the verifier's clock at all. This tool keeps the
  clock *close*, not *authenticated*.
* **Sanity bounds:** timestamps before 2026-01-01 or after 2100 are
  refused, so a zeroed or corrupted document can never move the clock to
  an absurd time.

## Development

```sh
nix develop            # toolchain
cargo test
cargo clippy --all-targets -- -D warnings
nix flake check        # tests, clippy, rustfmt, static build
```

The testable logic (offset math, decisions, document decoding, one round
over mock NSM and clock traits) lives in the library crate `timesync`
(`src/lib.rs`); `src/main.rs` is the CLI and daemon.

## License

Licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
* MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
