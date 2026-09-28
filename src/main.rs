//! Command-line daemon around the `timesync` library. See README.md.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use timesync::clock::KernelClock;
use timesync::decision::{Phase, NS_PER_MS};
use timesync::nsm::{Nsm, NSM_DEVICE};
use timesync::sync::{Backoff, Outcome, Settings, Syncer};

const NAME: &str = env!("CARGO_PKG_NAME");

/// Offsets at or above this are logged on every round; smaller ones only
/// in the periodic summary.
const NOTABLE_OFFSET_NS: i64 = 50 * NS_PER_MS;

/// Successful rounds between summary log lines (hourly at the default
/// interval).
const SUMMARY_EVERY: u32 = 60;

const BACKOFF_START: Duration = Duration::from_secs(1);
const BACKOFF_CAP: Duration = Duration::from_secs(300);

fn usage() -> String {
    let env = env_prefix();
    format!(
        "\
usage: {NAME} [options]

Keeps CLOCK_REALTIME on the Nitro hypervisor time read from /dev/nsm
attestation documents. Needs CAP_SYS_TIME.

By default the process forks: the parent waits (bounded) for the first
correction and exits 0, the child keeps the clock in sync.

options (each can also be set as an environment variable, shown in
brackets; command-line flags win):
  --oneshot                    one correction (step only, no PLL) in the
                               foreground, then exit [{env}ONESHOT=1]
  --foreground                 do not fork [{env}FOREGROUND=1]
  --no-slew                    never drive the kernel PLL; only step
                               [{env}NO_SLEW=1]
  --interval-secs N            seconds between rounds (default 60)
                               [{env}INTERVAL_SECS]
  --samples N                  attestation requests per round, 1-16
                               (default 3) [{env}SAMPLES]
  --max-rtt-ms N               discard samples slower than this
                               (default 1000) [{env}MAX_RTT_MS]
  --boot-step-threshold-ms N   first-round step threshold (default 100)
                               [{env}BOOT_STEP_THRESHOLD_MS]
  --step-threshold-ms N        later step threshold (default 500)
                               [{env}STEP_THRESHOLD_MS]
  --boot-wait-ms N             longest the forking parent waits for the
                               first round (default 5000) [{env}BOOT_WAIT_MS]
  --log-level FILTER           tracing filter, e.g. info, debug
                               (default info; RUST_LOG is honoured too)
                               [{env}LOG_LEVEL]
  -h, --help                   show this help
"
    )
}

/// Environment variable prefix derived from the package name, e.g.
/// `nitro-timesync` -> `NITRO_TIMESYNC_`.
fn env_prefix() -> String {
    format!("{}_", NAME.to_uppercase().replace('-', "_"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Fork, wait for the first round, keep syncing in the child.
    Daemon,
    /// Keep syncing in this process.
    Foreground,
    /// One step-only round in this process, then exit.
    Oneshot,
}

#[derive(Debug)]
struct Config {
    oneshot: bool,
    foreground: bool,
    boot_wait: Duration,
    log_level: Option<String>,
    settings: Settings,
}

impl Config {
    fn mode(&self) -> Mode {
        if self.oneshot {
            Mode::Oneshot
        } else if self.foreground {
            Mode::Foreground
        } else {
            Mode::Daemon
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            oneshot: false,
            foreground: false,
            boot_wait: Duration::from_millis(5000),
            log_level: None,
            settings: Settings::default(),
        }
    }
}

const BOOL_OPTIONS: &[&str] = &["oneshot", "foreground", "no-slew"];
const VALUE_OPTIONS: &[&str] = &[
    "interval-secs",
    "samples",
    "max-rtt-ms",
    "boot-step-threshold-ms",
    "step-threshold-ms",
    "boot-wait-ms",
    "log-level",
];

fn parse_bool(name: &str, raw: &str) -> Result<bool, String> {
    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        _ => Err(format!("{name}: not a boolean: {raw}")),
    }
}

fn parse_u64(name: &str, raw: &str) -> Result<u64, String> {
    raw.parse::<u64>()
        .map_err(|_| format!("{name}: not a number: {raw}"))
}

fn ms_to_ns(ms: u64) -> i64 {
    i64::try_from(ms)
        .unwrap_or(i64::MAX)
        .saturating_mul(NS_PER_MS)
}

/// Apply one option, given by its long name without dashes.
fn apply(cfg: &mut Config, name: &str, value: &str) -> Result<(), String> {
    let s = &mut cfg.settings;
    match name {
        "oneshot" => cfg.oneshot = parse_bool(name, value)?,
        "foreground" => cfg.foreground = parse_bool(name, value)?,
        "no-slew" => s.slew = !parse_bool(name, value)?,
        "interval-secs" => s.interval = Duration::from_secs(parse_u64(name, value)?.max(1)),
        "samples" => s.samples_per_round = parse_u64(name, value)?.clamp(1, 16) as u32,
        "max-rtt-ms" => s.max_rtt = Duration::from_millis(parse_u64(name, value)?),
        "boot-step-threshold-ms" => {
            s.policy.boot_step_threshold_ns = ms_to_ns(parse_u64(name, value)?)
        }
        "step-threshold-ms" => s.policy.step_threshold_ns = ms_to_ns(parse_u64(name, value)?),
        "boot-wait-ms" => cfg.boot_wait = Duration::from_millis(parse_u64(name, value)?),
        "log-level" => cfg.log_level = Some(value.to_string()),
        other => return Err(format!("unknown option: --{other}")),
    }
    Ok(())
}

/// Build the configuration from environment variables, then flags.
/// Returns `None` for `--help`.
fn parse_config(
    args: impl IntoIterator<Item = String>,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Option<Config>, String> {
    let mut cfg = Config::default();
    let prefix = env_prefix();
    for name in BOOL_OPTIONS.iter().chain(VALUE_OPTIONS) {
        let var = format!("{prefix}{}", name.to_uppercase().replace('-', "_"));
        if let Some(value) = env(&var) {
            apply(&mut cfg, name, &value).map_err(|e| format!("{var}: {e}"))?;
        }
    }

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            return Ok(None);
        }
        let Some(long) = arg.strip_prefix("--") else {
            return Err(format!("unexpected argument: {arg}"));
        };
        let (name, inline) = match long.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (long.to_string(), None),
        };
        if BOOL_OPTIONS.contains(&name.as_str()) {
            apply(&mut cfg, &name, inline.as_deref().unwrap_or("true"))?;
        } else if VALUE_OPTIONS.contains(&name.as_str()) {
            let value = match inline {
                Some(v) => v,
                None => args
                    .next()
                    .ok_or_else(|| format!("--{name} needs a value"))?,
            };
            apply(&mut cfg, &name, &value)?;
        } else {
            return Err(format!("unknown option: --{name}"));
        }
    }

    // A single round cannot run a control loop: one-shot never slews.
    if cfg.oneshot {
        cfg.settings.slew = false;
    }
    Ok(Some(cfg))
}

fn main() -> ExitCode {
    let cfg = match parse_config(std::env::args().skip(1), |k| std::env::var(k).ok()) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => {
            print!("{}", usage());
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("{NAME}: {e}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };

    if !Path::new(NSM_DEVICE).exists() {
        eprintln!("{NAME}: {NSM_DEVICE} not present; nothing to do");
        return ExitCode::SUCCESS;
    }

    match cfg.mode() {
        Mode::Oneshot => {
            init_logging(cfg.log_level.as_deref());
            oneshot(cfg.settings)
        }
        Mode::Foreground => {
            init_logging(cfg.log_level.as_deref());
            run(cfg.settings, None)
        }
        Mode::Daemon => daemonize(cfg),
    }
}

fn init_logging(level: Option<&str>) {
    let filter = level
        .and_then(|l| tracing_subscriber::EnvFilter::try_new(l).ok())
        .or_else(|| tracing_subscriber::EnvFilter::try_from_default_env().ok())
        .unwrap_or_else(|| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        // Enclave output usually lands on a serial console, where ANSI
        // escapes turn into literal garbage.
        .with_ansi(false)
        .init();
}

fn oneshot(settings: Settings) -> ExitCode {
    let mut syncer = Syncer::new(Nsm::default(), KernelClock, settings);
    match syncer.round(Phase::Boot) {
        Ok(outcome) => {
            log_outcome(&outcome, Phase::Boot, &mut 0);
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("clock sync failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Fork; the child runs the daemon, the parent waits (bounded) for the
/// child's first round and exits 0.
///
/// The fork happens before any thread exists, so the child is a clean
/// copy. A one-byte pipe carries "first round done"; EOF means the child
/// died before that.
fn daemonize(cfg: Config) -> ExitCode {
    let mut fds = [-1; 2];
    // SAFETY: `fds` is a valid two-element out-array.
    let piped = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == 0;

    // SAFETY: single-threaded at this point.
    match unsafe { libc::fork() } {
        -1 => {
            eprintln!(
                "{NAME}: fork failed: {}; clock sync disabled",
                std::io::Error::last_os_error()
            );
            ExitCode::SUCCESS
        }
        0 => {
            if piped {
                // SAFETY: closing our copy of the read end.
                unsafe { libc::close(fds[0]) };
            }
            // Own session: no controlling terminal, not in the caller's
            // process group.
            // SAFETY: plain syscall.
            unsafe { libc::setsid() };
            init_logging(cfg.log_level.as_deref());
            run(cfg.settings, piped.then_some(fds[1]))
        }
        _child => {
            if piped {
                // SAFETY: closing our copy of the write end, so EOF is seen
                // if the child dies.
                unsafe { libc::close(fds[1]) };
                wait_for_first_round(fds[0], cfg.boot_wait);
            }
            ExitCode::SUCCESS
        }
    }
}

fn wait_for_first_round(fd: i32, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = remaining.as_millis().min(i32::MAX as u128) as libc::c_int;
        // SAFETY: one valid pollfd.
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if rc == 0 {
            eprintln!(
                "{NAME}: first round not done after {} ms; returning",
                timeout.as_millis()
            );
        }
        break;
    }
    // SAFETY: closing the read end we own.
    unsafe { libc::close(fd) };
}

/// Tell the waiting parent the first round is over (whatever its result).
fn release_parent(fd: &mut Option<i32>) {
    if let Some(fd) = fd.take() {
        // SAFETY: `fd` is the pipe's write end, owned by us. A failed write
        // (parent already gone) is irrelevant; SIGPIPE is ignored by the
        // Rust runtime.
        unsafe {
            libc::write(fd, [1u8].as_ptr().cast(), 1);
            libc::close(fd);
        }
    }
}

fn run(settings: Settings, mut first_round_signal: Option<i32>) -> ! {
    let mut syncer = Syncer::new(Nsm::default(), KernelClock, settings);
    let interval = syncer.settings().interval;
    info!(
        interval_secs = interval.as_secs(),
        samples = settings.samples_per_round,
        slew = settings.slew,
        boot_step_ms = settings.policy.boot_step_threshold_ns / NS_PER_MS,
        step_ms = settings.policy.step_threshold_ns / NS_PER_MS,
        "{NAME} {} starting",
        env!("CARGO_PKG_VERSION")
    );

    let mut phase = Phase::Boot;
    let mut backoff = Backoff::new(BACKOFF_START, BACKOFF_CAP.max(interval));
    let mut rounds_since_summary = 0u32;
    let mut announced_emulated = false;

    loop {
        let delay = match syncer.round(phase) {
            Ok(outcome) => {
                if outcome.measurement().coarse && !announced_emulated {
                    announced_emulated = true;
                    info!(
                        "emulated NSM (whole-second timestamps): stepping only, \
                         never slewing"
                    );
                }
                rounds_since_summary += 1;
                log_outcome(&outcome, phase, &mut rounds_since_summary);
                phase = Phase::Steady;
                backoff.reset();
                interval
            }
            Err(e) => {
                let d = backoff.next_delay();
                warn!(retry_in_secs = d.as_secs(), "clock sync round failed: {e}");
                d
            }
        };
        release_parent(&mut first_round_signal);
        // Relative sleeps run on CLOCK_MONOTONIC, so our own steps do not
        // stretch or shorten them.
        std::thread::sleep(delay);
    }
}

fn log_outcome(outcome: &Outcome, phase: Phase, rounds_since_summary: &mut u32) {
    let m = outcome.measurement();
    let offset_ms = m.offset_ns as f64 / NS_PER_MS as f64;
    let rtt_ms = m.rtt_ns as f64 / NS_PER_MS as f64;
    let loud = phase == Phase::Boot || *rounds_since_summary >= SUMMARY_EVERY;
    match outcome {
        Outcome::Stepped { .. } => {
            info!(offset_ms, rtt_ms, ?phase, "stepped clock");
            *rounds_since_summary = 0;
        }
        Outcome::Slewed { pll, .. } => {
            let freq_ppm = pll.freq_ppm;
            if loud || m.offset_ns.abs() >= NOTABLE_OFFSET_NS {
                info!(offset_ms, rtt_ms, freq_ppm, "slewing clock");
                *rounds_since_summary = 0;
            } else {
                debug!(offset_ms, rtt_ms, freq_ppm, "slewing clock");
            }
        }
        Outcome::Held { .. } => {
            if loud {
                info!(
                    offset_ms,
                    rtt_ms, "offset below the step threshold; clock left alone"
                );
                *rounds_since_summary = 0;
            } else {
                debug!(
                    offset_ms,
                    rtt_ms, "offset below the step threshold; clock left alone"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn parse_with_env(args: &[&str], env: &[(&str, &str)]) -> Result<Option<Config>, String> {
        let env: HashMap<String, String> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        parse_config(args.iter().map(|s| s.to_string()), |k| env.get(k).cloned())
    }

    fn parse(args: &[&str]) -> Result<Option<Config>, String> {
        parse_with_env(args, &[])
    }

    #[test]
    fn env_prefix_follows_the_package_name() {
        assert_eq!(env_prefix(), "NITRO_TIMESYNC_");
    }

    #[test]
    fn defaults() {
        let cfg = parse(&[]).unwrap().unwrap();
        assert_eq!(cfg.mode(), Mode::Daemon);
        assert_eq!(cfg.boot_wait, Duration::from_secs(5));
        assert_eq!(cfg.log_level, None);
        assert_eq!(cfg.settings, Settings::default());
        assert!(cfg.settings.slew);
    }

    #[test]
    fn flags_in_both_spellings() {
        let cfg = parse(&[
            "--foreground",
            "--interval-secs",
            "30",
            "--samples=5",
            "--step-threshold-ms=1000",
            "--boot-step-threshold-ms",
            "50",
            "--max-rtt-ms=250",
            "--boot-wait-ms=0",
            "--log-level=debug",
            "--no-slew",
        ])
        .unwrap()
        .unwrap();
        assert_eq!(cfg.mode(), Mode::Foreground);
        assert_eq!(cfg.settings.interval, Duration::from_secs(30));
        assert_eq!(cfg.settings.samples_per_round, 5);
        assert_eq!(cfg.settings.policy.step_threshold_ns, 1000 * NS_PER_MS);
        assert_eq!(cfg.settings.policy.boot_step_threshold_ns, 50 * NS_PER_MS);
        assert_eq!(cfg.settings.max_rtt, Duration::from_millis(250));
        assert_eq!(cfg.boot_wait, Duration::ZERO);
        assert_eq!(cfg.log_level.as_deref(), Some("debug"));
        assert!(!cfg.settings.slew);
    }

    #[test]
    fn environment_sets_options_and_flags_override_it() {
        let env = [
            ("NITRO_TIMESYNC_INTERVAL_SECS", "120"),
            ("NITRO_TIMESYNC_STEP_THRESHOLD_MS", "2000"),
            ("NITRO_TIMESYNC_FOREGROUND", "yes"),
            ("NITRO_TIMESYNC_LOG_LEVEL", "warn"),
        ];
        let cfg = parse_with_env(&["--interval-secs=10"], &env)
            .unwrap()
            .unwrap();
        assert_eq!(cfg.settings.interval, Duration::from_secs(10));
        assert_eq!(cfg.settings.policy.step_threshold_ns, 2000 * NS_PER_MS);
        assert_eq!(cfg.mode(), Mode::Foreground);
        assert_eq!(cfg.log_level.as_deref(), Some("warn"));
    }

    #[test]
    fn bad_environment_values_name_the_variable() {
        let err = parse_with_env(&[], &[("NITRO_TIMESYNC_SAMPLES", "many")]).unwrap_err();
        assert!(err.starts_with("NITRO_TIMESYNC_SAMPLES"), "{err}");
        assert!(parse_with_env(&[], &[("NITRO_TIMESYNC_ONESHOT", "maybe")]).is_err());
    }

    #[test]
    fn oneshot_wins_and_never_slews() {
        let cfg = parse(&["--oneshot", "--foreground"]).unwrap().unwrap();
        assert_eq!(cfg.mode(), Mode::Oneshot);
        assert!(!cfg.settings.slew);
        let cfg = parse_with_env(&[], &[("NITRO_TIMESYNC_ONESHOT", "1")])
            .unwrap()
            .unwrap();
        assert_eq!(cfg.mode(), Mode::Oneshot);
        // An explicit false flag overrides the environment.
        let cfg = parse_with_env(&["--oneshot=false"], &[("NITRO_TIMESYNC_ONESHOT", "1")])
            .unwrap()
            .unwrap();
        assert_eq!(cfg.mode(), Mode::Daemon);
        assert!(cfg.settings.slew);
    }

    #[test]
    fn bad_input_is_rejected() {
        assert!(parse(&["--bogus"]).is_err());
        assert!(parse(&["positional"]).is_err());
        assert!(parse(&["--interval-secs"]).is_err());
        assert!(parse(&["--interval-secs=abc"]).is_err());
        assert!(parse(&["--help"]).unwrap().is_none());
        assert!(parse(&["-h"]).unwrap().is_none());
    }

    #[test]
    fn out_of_range_values_are_clamped() {
        let cfg = parse(&["--interval-secs=0", "--samples=100"])
            .unwrap()
            .unwrap();
        assert_eq!(cfg.settings.interval, Duration::from_secs(1));
        assert_eq!(cfg.settings.samples_per_round, 16);
        let cfg = parse(&["--samples=0"]).unwrap().unwrap();
        assert_eq!(cfg.settings.samples_per_round, 1);
    }
}
