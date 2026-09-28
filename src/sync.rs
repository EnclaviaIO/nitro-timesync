//! One synchronisation round: sample the NSM a few times, keep the
//! tightest sample, decide, and apply.

use std::time::Duration;

use crate::clock::{Clock, PllState};
use crate::decision::{self, Action, Measurement, Phase, Policy, Sample};
use crate::doc;
use crate::nsm::AttestationSource;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Settings {
    pub interval: Duration,
    /// Attestation requests per round; the one with the shortest round
    /// trip is used.
    pub samples_per_round: u32,
    /// Samples whose round trip exceeds this are discarded.
    pub max_rtt: Duration,
    /// Whether to drive the kernel PLL. When false, offsets below the
    /// step threshold are left alone and steps do not touch the PLL.
    pub slew: bool,
    pub policy: Policy,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60),
            samples_per_round: 3,
            max_rtt: Duration::from_secs(1),
            slew: true,
            policy: Policy::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Outcome {
    Stepped {
        measurement: Measurement,
    },
    Slewed {
        measurement: Measurement,
        pll: PllState,
    },
    Held {
        measurement: Measurement,
    },
}

impl Outcome {
    pub fn measurement(&self) -> &Measurement {
        match self {
            Self::Stepped { measurement }
            | Self::Slewed { measurement, .. }
            | Self::Held { measurement } => measurement,
        }
    }
}

#[derive(Debug)]
pub enum RoundError {
    /// No usable sample: every request failed or was rejected. Carries the
    /// last reason.
    NoSample(String),
    /// The kernel refused the adjustment.
    Clock(std::io::Error),
}

impl std::fmt::Display for RoundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSample(reason) => write!(f, "no usable NSM sample: {reason}"),
            Self::Clock(e) => write!(f, "adjusting the clock failed: {e}"),
        }
    }
}

pub struct Syncer<S, C> {
    source: S,
    clock: C,
    settings: Settings,
    time_constant: i64,
}

impl<S: AttestationSource, C: Clock> Syncer<S, C> {
    pub fn new(source: S, clock: C, settings: Settings) -> Self {
        let time_constant = decision::pll_time_constant(settings.interval.as_secs());
        Self {
            source,
            clock,
            settings,
            time_constant,
        }
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// One bracketed request. The document is decoded only after the
    /// second clock read so decoding time does not widen the bracket.
    fn sample(&mut self) -> Result<Measurement, String> {
        let before = self.clock.realtime_ns();
        let document = self.source.attest()?;
        let after = self.clock.realtime_ns();
        let t = doc::parse(&document)?;
        Sample {
            local_before_ns: before,
            local_after_ns: after,
            nsm_timestamp_ms: t.timestamp_ms,
            resolution_ms: t.resolution_ms,
        }
        .measure(duration_ns(self.settings.max_rtt))
        .map_err(|e| e.to_string())
    }

    pub fn round(&mut self, phase: Phase) -> Result<Outcome, RoundError> {
        let mut measurements = Vec::new();
        let mut last_error = String::from("no samples requested");
        for _ in 0..self.settings.samples_per_round.max(1) {
            match self.sample() {
                Ok(m) => measurements.push(m),
                Err(e) => last_error = e,
            }
        }
        let Some(m) = decision::best(&measurements) else {
            return Err(RoundError::NoSample(last_error));
        };

        let pll = self.settings.slew.then_some(self.time_constant);
        match decision::decide(&m, phase, &self.settings.policy) {
            Action::Step(delta) => {
                self.clock.step(delta, pll).map_err(RoundError::Clock)?;
                Ok(Outcome::Stepped { measurement: m })
            }
            Action::Slew(_) if !self.settings.slew => Ok(Outcome::Held { measurement: m }),
            Action::Slew(offset) => {
                let pll = self
                    .clock
                    .slew(offset, self.time_constant)
                    .map_err(RoundError::Clock)?;
                Ok(Outcome::Slewed {
                    measurement: m,
                    pll,
                })
            }
            Action::Hold => Ok(Outcome::Held { measurement: m }),
        }
    }
}

fn duration_ns(d: Duration) -> i64 {
    i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)
}

/// Retry delay after failed rounds: doubles from `start` up to `cap`.
pub struct Backoff {
    start: Duration,
    cap: Duration,
    next: Duration,
}

impl Backoff {
    pub fn new(start: Duration, cap: Duration) -> Self {
        Self {
            start,
            cap,
            next: start,
        }
    }

    pub fn next_delay(&mut self) -> Duration {
        let d = self.next;
        self.next = (self.next * 2).min(self.cap);
        d
    }

    pub fn reset(&mut self) {
        self.next = self.start;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{MIN_PLAUSIBLE_TIMESTAMP_MS, NS_PER_MS, NS_PER_SEC};
    use ciborium::Value;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::io;
    use std::rc::Rc;

    const T0_MS: u64 = 1_800_000_000_000;
    const T0_NS: i64 = T0_MS as i64 * NS_PER_MS;

    fn nitro_doc(ts_ms: u64) -> Vec<u8> {
        doc::encode_for_test(Value::Integer(ts_ms.into()), Some(vec![0x30, 0x82]), false)
    }

    fn emulated_doc(ts_ms: u64) -> Vec<u8> {
        doc::encode_for_test(Value::Integer(ts_ms.into()), Some(vec![0; 64]), false)
    }

    /// Each attest() advances the shared fake clock by the scripted
    /// latency, then returns the scripted document.
    struct FakeSource {
        now: Rc<Cell<i64>>,
        script: VecDeque<(i64, Result<Vec<u8>, String>)>,
    }

    impl AttestationSource for FakeSource {
        fn attest(&mut self) -> Result<Vec<u8>, String> {
            let (latency, doc) = self.script.pop_front().expect("unscripted attest");
            self.now.set(self.now.get() + latency);
            doc
        }
    }

    #[derive(Debug, PartialEq)]
    enum Call {
        Step(i64, Option<i64>),
        Slew(i64, i64),
    }

    struct FakeClock {
        now: Rc<Cell<i64>>,
        calls: Vec<Call>,
        fail: bool,
    }

    impl Clock for FakeClock {
        fn realtime_ns(&self) -> i64 {
            self.now.get()
        }
        fn step(&mut self, delta_ns: i64, tc: Option<i64>) -> io::Result<()> {
            if self.fail {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            self.calls.push(Call::Step(delta_ns, tc));
            self.now.set(self.now.get() + delta_ns);
            Ok(())
        }
        fn slew(&mut self, offset_ns: i64, tc: i64) -> io::Result<PllState> {
            if self.fail {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            self.calls.push(Call::Slew(offset_ns, tc));
            Ok(PllState { freq_ppm: 0.0 })
        }
    }

    fn syncer(
        start_ns: i64,
        script: Vec<(i64, Result<Vec<u8>, String>)>,
    ) -> Syncer<FakeSource, FakeClock> {
        let now = Rc::new(Cell::new(start_ns));
        Syncer::new(
            FakeSource {
                now: now.clone(),
                script: script.into(),
            },
            FakeClock {
                now,
                calls: vec![],
                fail: false,
            },
            Settings::default(),
        )
    }

    #[test]
    fn boot_round_steps_a_clock_that_is_seconds_slow() {
        // Local clock 15 s behind; each request takes 10 ms and the NSM
        // stamps mid-request.
        let local = T0_NS - 15 * NS_PER_SEC;
        let mut s = syncer(
            local,
            vec![
                (10 * NS_PER_MS, Ok(nitro_doc(T0_MS + 5))),
                (10 * NS_PER_MS, Ok(nitro_doc(T0_MS + 15))),
                (10 * NS_PER_MS, Ok(nitro_doc(T0_MS + 25))),
            ],
        );
        let out = s.round(Phase::Boot).unwrap();
        assert!(matches!(out, Outcome::Stepped { .. }));
        let offset = out.measurement().offset_ns;
        assert_eq!(offset, 15 * NS_PER_SEC + NS_PER_MS / 2);
        assert_eq!(s.clock.calls, vec![Call::Step(offset, Some(6))]);
    }

    #[test]
    fn steady_round_slews_small_drift() {
        let local = T0_NS - 3 * NS_PER_MS;
        let mut s = syncer(
            local,
            vec![
                (2 * NS_PER_MS, Ok(nitro_doc(T0_MS + 1))),
                (2 * NS_PER_MS, Ok(nitro_doc(T0_MS + 3))),
                (2 * NS_PER_MS, Ok(nitro_doc(T0_MS + 5))),
            ],
        );
        let out = s.round(Phase::Steady).unwrap();
        assert!(matches!(out, Outcome::Slewed { .. }));
        assert_eq!(s.clock.calls.len(), 1);
        assert!(matches!(s.clock.calls[0], Call::Slew(o, 6) if o > 0 && o < 5 * NS_PER_MS));
    }

    #[test]
    fn round_uses_the_fastest_sample() {
        // Three samples with increasingly bad latency; the NSM stamp of
        // the slow ones lands late in the bracket and would overstate the
        // offset. The fastest one wins.
        let mut s = syncer(
            T0_NS,
            vec![
                (400 * NS_PER_MS, Ok(nitro_doc(T0_MS + 400))),
                (2 * NS_PER_MS, Ok(nitro_doc(T0_MS + 401))),
                (300 * NS_PER_MS, Ok(nitro_doc(T0_MS + 702))),
            ],
        );
        let out = s.round(Phase::Steady).unwrap();
        assert_eq!(out.measurement().rtt_ns, 2 * NS_PER_MS);
    }

    #[test]
    fn a_failed_request_in_the_round_is_tolerated() {
        let mut s = syncer(
            T0_NS,
            vec![
                (NS_PER_MS, Err("transient".into())),
                (NS_PER_MS, Ok(nitro_doc(T0_MS + 1))),
                (NS_PER_MS, Ok(vec![0xff])),
            ],
        );
        assert!(matches!(s.round(Phase::Steady), Ok(Outcome::Slewed { .. })));
    }

    #[test]
    fn a_round_without_usable_samples_changes_nothing() {
        let mut s = syncer(
            T0_NS,
            vec![
                (NS_PER_MS, Err("nsm down".into())),
                (NS_PER_MS, Ok(nitro_doc(0))),
                (NS_PER_MS, Ok(nitro_doc(MIN_PLAUSIBLE_TIMESTAMP_MS - 1))),
            ],
        );
        match s.round(Phase::Boot) {
            Err(RoundError::NoSample(reason)) => assert!(reason.contains("implausibly early")),
            other => panic!("expected NoSample, got {other:?}"),
        }
        assert!(s.clock.calls.is_empty());
    }

    #[test]
    fn emulated_nsm_holds_small_offsets_and_steps_large_ones() {
        let mut s = syncer(
            T0_NS,
            vec![
                (NS_PER_MS, Ok(emulated_doc(T0_MS))),
                (NS_PER_MS, Ok(emulated_doc(T0_MS))),
                (NS_PER_MS, Ok(emulated_doc(T0_MS))),
            ],
        );
        assert!(matches!(s.round(Phase::Boot), Ok(Outcome::Held { .. })));
        assert!(s.clock.calls.is_empty());

        let mut s = syncer(
            T0_NS - 30 * NS_PER_SEC,
            vec![
                (NS_PER_MS, Ok(emulated_doc(T0_MS))),
                (NS_PER_MS, Ok(emulated_doc(T0_MS))),
                (NS_PER_MS, Ok(emulated_doc(T0_MS))),
            ],
        );
        assert!(matches!(
            s.round(Phase::Steady),
            Ok(Outcome::Stepped { .. })
        ));
        assert!(matches!(s.clock.calls[..], [Call::Step(..)]));
    }

    #[test]
    fn clock_errors_are_reported_not_panicked() {
        let mut s = syncer(
            T0_NS - 10 * NS_PER_SEC,
            vec![
                (NS_PER_MS, Ok(nitro_doc(T0_MS))),
                (NS_PER_MS, Ok(nitro_doc(T0_MS))),
                (NS_PER_MS, Ok(nitro_doc(T0_MS))),
            ],
        );
        s.clock.fail = true;
        assert!(matches!(s.round(Phase::Boot), Err(RoundError::Clock(_))));
    }

    #[test]
    fn without_slew_small_offsets_are_held_and_steps_skip_the_pll() {
        let script = || {
            vec![
                (NS_PER_MS, Ok(nitro_doc(T0_MS))),
                (NS_PER_MS, Ok(nitro_doc(T0_MS))),
                (NS_PER_MS, Ok(nitro_doc(T0_MS))),
            ]
        };
        let mut s = syncer(T0_NS - 20 * NS_PER_MS, script());
        s.settings.slew = false;
        assert!(matches!(s.round(Phase::Boot), Ok(Outcome::Held { .. })));
        assert!(s.clock.calls.is_empty());

        let mut s = syncer(T0_NS - 5 * NS_PER_SEC, script());
        s.settings.slew = false;
        assert!(matches!(s.round(Phase::Boot), Ok(Outcome::Stepped { .. })));
        assert!(matches!(s.clock.calls[..], [Call::Step(_, None)]));
    }

    #[test]
    fn backoff_doubles_to_the_cap_and_resets() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(5));
        let got: Vec<u64> = (0..5).map(|_| b.next_delay().as_secs()).collect();
        assert_eq!(got, vec![1, 2, 4, 5, 5]);
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_secs(1));
    }
}
