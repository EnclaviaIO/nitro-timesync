# Changelog

All notable changes to this project are documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - unreleased

### Added

- Daemon that keeps `CLOCK_REALTIME` on the Nitro hypervisor time read
  from `/dev/nsm` attestation documents: a boot step above 100 ms, then the
  kernel PLL every 60 s, stepping only above 500 ms.
- Best-of-3 sampling per round with a round-trip-midpoint offset, and
  sanity bounds on the timestamp and the round trip.
- Detection of QEMU's emulated NSM (whole-second timestamps): step only,
  above 2 s.
- Daemon (fork, bounded wait for the first round), `--foreground` and
  `--oneshot` modes; `--no-slew`; configuration by flags or
  `NITRO_TIMESYNC_*` environment variables; `--log-level`.
- Nix flake with native and static musl packages and checks.
