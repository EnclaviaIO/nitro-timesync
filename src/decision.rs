//! Offset math and the step / slew / hold decision. Pure functions only:
//! everything here is unit-tested without touching a clock or /dev/nsm.
//!
//! All times are signed nanoseconds since the Unix epoch (`i64` covers
//! 1677..2262, far wider than the plausibility window below).

pub const NS_PER_MS: i64 = 1_000_000;
pub const NS_PER_SEC: i64 = 1_000_000_000;

/// Earliest NSM `timestamp` accepted, in ms since the epoch
/// (2026-01-01T00:00:00Z). Every genuine document this binary can see is
/// produced after the binary was built, so anything earlier is a zero,
/// uninitialised or otherwise bogus value and must never move the clock.
pub const MIN_PLAUSIBLE_TIMESTAMP_MS: u64 = 1_767_225_600_000;

/// Latest NSM `timestamp` accepted, in ms since the epoch
/// (2100-01-01T00:00:00Z). Guards the other direction against garbage.
pub const MAX_PLAUSIBLE_TIMESTAMP_MS: u64 = 4_102_444_800_000;

/// Resolution of the real Nitro NSM `timestamp`: milliseconds.
pub const NITRO_RESOLUTION_MS: u64 = 1;

/// Resolution of QEMU's emulated NSM `timestamp`: it stamps
/// `time(NULL) * 1000`, i.e. whole seconds of the QEMU host's clock.
pub const EMULATED_RESOLUTION_MS: u64 = 1_000;

/// One NSM reading bracketed by two reads of the local realtime clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    /// Local CLOCK_REALTIME just before the attestation request.
    pub local_before_ns: i64,
    /// Local CLOCK_REALTIME just after the attestation response.
    pub local_after_ns: i64,
    /// The document's `timestamp` field (ms since the epoch).
    pub nsm_timestamp_ms: u64,
    /// Granularity of `nsm_timestamp_ms`; the true instant lies in
    /// `[timestamp, timestamp + resolution)`.
    pub resolution_ms: u64,
}

/// What a valid sample says about the local clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Measurement {
    /// NSM time minus local time. Positive: the local clock is behind.
    pub offset_ns: i64,
    /// Local round trip of the attestation request.
    pub rtt_ns: i64,
    /// Bound on how far `offset_ns` can be from the true offset: the NSM
    /// stamp may have been taken anywhere inside the round trip, and
    /// anywhere inside its own resolution bucket.
    pub uncertainty_ns: i64,
    /// Whether the reading came from a coarse (emulated) NSM.
    pub coarse: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SampleError {
    /// `timestamp` is zero or before [`MIN_PLAUSIBLE_TIMESTAMP_MS`].
    TooEarly { timestamp_ms: u64 },
    /// `timestamp` is after [`MAX_PLAUSIBLE_TIMESTAMP_MS`].
    TooLate { timestamp_ms: u64 },
    /// The local clock moved backwards across the request (someone else
    /// stepped it); the bracket is meaningless.
    LocalClockWentBackwards,
    /// The request took longer than the configured bound, so the midpoint
    /// estimate is too loose to act on.
    RoundTripTooSlow { rtt_ns: i64, max_rtt_ns: i64 },
}

impl std::fmt::Display for SampleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooEarly { timestamp_ms } => {
                write!(f, "NSM timestamp {timestamp_ms} ms is implausibly early")
            }
            Self::TooLate { timestamp_ms } => {
                write!(f, "NSM timestamp {timestamp_ms} ms is implausibly late")
            }
            Self::LocalClockWentBackwards => {
                write!(f, "local clock went backwards during the request")
            }
            Self::RoundTripTooSlow { rtt_ns, max_rtt_ns } => write!(
                f,
                "request round trip {} ms exceeds {} ms",
                rtt_ns / NS_PER_MS,
                max_rtt_ns / NS_PER_MS
            ),
        }
    }
}

impl Sample {
    /// Turn a raw sample into an offset estimate.
    ///
    /// The NSM stamp is compared against the midpoint of the local
    /// before/after reads, which assumes the stamp was taken halfway
    /// through the request; the error of that assumption is at most half
    /// the round trip. The stamp itself is floored to its resolution, so
    /// the centre of the bucket is used.
    pub fn measure(&self, max_rtt_ns: i64) -> Result<Measurement, SampleError> {
        let ts = self.nsm_timestamp_ms;
        if ts < MIN_PLAUSIBLE_TIMESTAMP_MS {
            return Err(SampleError::TooEarly { timestamp_ms: ts });
        }
        if ts > MAX_PLAUSIBLE_TIMESTAMP_MS {
            return Err(SampleError::TooLate { timestamp_ms: ts });
        }
        let rtt_ns = self.local_after_ns - self.local_before_ns;
        if rtt_ns < 0 {
            return Err(SampleError::LocalClockWentBackwards);
        }
        if rtt_ns > max_rtt_ns {
            return Err(SampleError::RoundTripTooSlow { rtt_ns, max_rtt_ns });
        }

        let resolution_ns = self.resolution_ms as i64 * NS_PER_MS;
        // Bounded by MAX_PLAUSIBLE_TIMESTAMP_MS, so no overflow.
        let nsm_ns = ts as i64 * NS_PER_MS + resolution_ns / 2;
        let local_mid_ns = self.local_before_ns + rtt_ns / 2;
        Ok(Measurement {
            offset_ns: nsm_ns - local_mid_ns,
            rtt_ns,
            uncertainty_ns: rtt_ns / 2 + resolution_ns / 2,
            coarse: self.resolution_ms > NITRO_RESOLUTION_MS,
        })
    }
}

/// Of several measurements taken back to back, the one with the shortest
/// round trip has the tightest midpoint bound, so it is the one to trust.
pub fn best(measurements: &[Measurement]) -> Option<Measurement> {
    measurements.iter().copied().min_by_key(|m| m.rtt_ns)
}

/// Whether the daemon has already brought the clock in line once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// No successful correction yet: nothing that reads the clock has run
    /// long enough to be hurt by a small step, so step more eagerly.
    Boot,
    /// The clock has been corrected before; prefer slewing.
    Steady,
}

/// Thresholds for choosing between a step and a slew.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Step at boot when the offset is certainly larger than this.
    pub boot_step_threshold_ns: i64,
    /// Step in steady state when the offset is certainly larger than this.
    pub step_threshold_ns: i64,
    /// Step threshold used for coarse (emulated) readings, in any phase.
    pub coarse_step_threshold_ns: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            boot_step_threshold_ns: 100 * NS_PER_MS,
            // The kernel PLL clamps any single offset to MAXPHASE (500 ms),
            // so a larger error cannot be slewed in one update anyway.
            step_threshold_ns: 500 * NS_PER_MS,
            coarse_step_threshold_ns: 2 * NS_PER_SEC,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Jump the clock by this many nanoseconds.
    Step(i64),
    /// Hand this offset to the kernel PLL.
    Slew(i64),
    /// Leave the clock alone.
    Hold,
}

/// Decide what to do with a measurement.
///
/// A step is taken only when the offset is larger than the threshold even
/// after subtracting the measurement's uncertainty, so a slow request can
/// never trigger one on its own. Coarse readings are never slewed: their
/// one-second quantisation would make the PLL chase noise.
pub fn decide(m: &Measurement, phase: Phase, policy: &Policy) -> Action {
    let threshold = if m.coarse {
        policy.coarse_step_threshold_ns
    } else {
        match phase {
            Phase::Boot => policy.boot_step_threshold_ns,
            Phase::Steady => policy.step_threshold_ns,
        }
    };
    let certain_ns = m.offset_ns.saturating_abs() - m.uncertainty_ns;
    if certain_ns > threshold {
        Action::Step(m.offset_ns)
    } else if m.coarse {
        Action::Hold
    } else {
        Action::Slew(m.offset_ns)
    }
}

/// Kernel PLL time constant for a given poll interval.
///
/// The kernel's phase correction decays with a period of
/// `2^(SHIFT_PLL + constant)` seconds (SHIFT_PLL = 2) and its frequency
/// gain scales with `2^-2(constant + 4)`; ntpd pairs a poll of `2^n`
/// seconds with constant `n` in nanosecond mode, which keeps the loop
/// stable. Round the interval to the nearest power of two and clamp to the
/// kernel's range (MAXTC = 10).
pub fn pll_time_constant(interval_secs: u64) -> i64 {
    if interval_secs <= 1 {
        return 0;
    }
    let log2 = (interval_secs as f64).log2().round() as i64;
    log2.clamp(0, 10)
}

/// Split a signed nanosecond delta into the `(seconds, nanoseconds)` form
/// ADJ_SETOFFSET requires: the sub-second part must be in `[0, 1e9)`, with
/// the sign carried by the seconds.
pub fn split_delta(delta_ns: i64) -> (i64, i64) {
    (
        delta_ns.div_euclid(NS_PER_SEC),
        delta_ns.rem_euclid(NS_PER_SEC),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0_MS: u64 = 1_800_000_000_000;
    const T0_NS: i64 = T0_MS as i64 * NS_PER_MS;

    fn sample(before_ns: i64, after_ns: i64, ts_ms: u64) -> Sample {
        Sample {
            local_before_ns: before_ns,
            local_after_ns: after_ns,
            nsm_timestamp_ms: ts_ms,
            resolution_ms: NITRO_RESOLUTION_MS,
        }
    }

    #[test]
    fn offset_uses_the_round_trip_midpoint() {
        // Local clock reads T0-20ms .. T0+20ms around the request; NSM says
        // T0 + 5 s. The midpoint is T0, so the clock is 5 s (+0.5 ms bucket
        // centre) behind.
        let s = sample(
            T0_NS - 20 * NS_PER_MS,
            T0_NS + 20 * NS_PER_MS,
            T0_MS + 5_000,
        );
        let m = s.measure(NS_PER_SEC).unwrap();
        assert_eq!(m.offset_ns, 5 * NS_PER_SEC + NS_PER_MS / 2);
        assert_eq!(m.rtt_ns, 40 * NS_PER_MS);
        assert_eq!(m.uncertainty_ns, 20 * NS_PER_MS + NS_PER_MS / 2);
        assert!(!m.coarse);
    }

    #[test]
    fn negative_offset_when_local_clock_is_ahead() {
        let s = sample(T0_NS + 3 * NS_PER_SEC, T0_NS + 3 * NS_PER_SEC, T0_MS);
        let m = s.measure(NS_PER_SEC).unwrap();
        assert_eq!(m.offset_ns, -3 * NS_PER_SEC + NS_PER_MS / 2);
    }

    #[test]
    fn midpoint_of_odd_round_trip_rounds_toward_before() {
        let s = sample(T0_NS, T0_NS + 3, T0_MS);
        let m = s.measure(NS_PER_SEC).unwrap();
        // mid = T0 + 1; bucket centre = T0 + 0.5 ms.
        assert_eq!(m.offset_ns, NS_PER_MS / 2 - 1);
    }

    #[test]
    fn emulated_resolution_centres_the_second() {
        let s = Sample {
            local_before_ns: T0_NS,
            local_after_ns: T0_NS,
            nsm_timestamp_ms: T0_MS,
            resolution_ms: EMULATED_RESOLUTION_MS,
        };
        let m = s.measure(NS_PER_SEC).unwrap();
        assert_eq!(m.offset_ns, 500 * NS_PER_MS);
        assert_eq!(m.uncertainty_ns, 500 * NS_PER_MS);
        assert!(m.coarse);
    }

    #[test]
    fn zero_and_early_timestamps_are_rejected() {
        assert_eq!(
            sample(T0_NS, T0_NS, 0).measure(NS_PER_SEC),
            Err(SampleError::TooEarly { timestamp_ms: 0 })
        );
        let early = MIN_PLAUSIBLE_TIMESTAMP_MS - 1;
        assert_eq!(
            sample(T0_NS, T0_NS, early).measure(NS_PER_SEC),
            Err(SampleError::TooEarly {
                timestamp_ms: early
            })
        );
        assert!(sample(T0_NS, T0_NS, MIN_PLAUSIBLE_TIMESTAMP_MS)
            .measure(NS_PER_SEC)
            .is_ok());
    }

    #[test]
    fn far_future_timestamps_are_rejected() {
        let late = MAX_PLAUSIBLE_TIMESTAMP_MS + 1;
        assert_eq!(
            sample(T0_NS, T0_NS, late).measure(NS_PER_SEC),
            Err(SampleError::TooLate { timestamp_ms: late })
        );
        assert!(sample(T0_NS, T0_NS, u64::MAX).measure(NS_PER_SEC).is_err());
    }

    #[test]
    fn backwards_local_clock_is_rejected() {
        assert_eq!(
            sample(T0_NS, T0_NS - 1, T0_MS).measure(NS_PER_SEC),
            Err(SampleError::LocalClockWentBackwards)
        );
    }

    #[test]
    fn slow_round_trip_is_rejected() {
        let s = sample(T0_NS, T0_NS + 2 * NS_PER_SEC, T0_MS);
        assert_eq!(
            s.measure(NS_PER_SEC),
            Err(SampleError::RoundTripTooSlow {
                rtt_ns: 2 * NS_PER_SEC,
                max_rtt_ns: NS_PER_SEC
            })
        );
        assert!(s.measure(2 * NS_PER_SEC).is_ok());
    }

    #[test]
    fn a_local_clock_before_the_epoch_still_measures() {
        // A clock that booted at 1970 (or earlier) is exactly the case the
        // boot step exists for.
        let s = sample(-5 * NS_PER_SEC, -5 * NS_PER_SEC, T0_MS);
        let m = s.measure(NS_PER_SEC).unwrap();
        assert_eq!(m.offset_ns, T0_NS + 5 * NS_PER_SEC + NS_PER_MS / 2);
    }

    #[test]
    fn best_picks_the_shortest_round_trip() {
        let m = |offset_ns, rtt_ns| Measurement {
            offset_ns,
            rtt_ns,
            uncertainty_ns: rtt_ns / 2,
            coarse: false,
        };
        let all = [m(10, 300), m(20, 100), m(30, 200)];
        assert_eq!(best(&all).unwrap().offset_ns, 20);
        assert_eq!(best(&[]), None);
    }

    fn meas(offset_ns: i64, uncertainty_ns: i64, coarse: bool) -> Measurement {
        Measurement {
            offset_ns,
            rtt_ns: 2 * uncertainty_ns,
            uncertainty_ns,
            coarse,
        }
    }

    #[test]
    fn boot_steps_above_the_boot_threshold() {
        let p = Policy::default();
        let m = meas(150 * NS_PER_MS, NS_PER_MS, false);
        assert_eq!(decide(&m, Phase::Boot, &p), Action::Step(150 * NS_PER_MS));
        // Same offset in steady state is slewed.
        assert_eq!(decide(&m, Phase::Steady, &p), Action::Slew(150 * NS_PER_MS));
    }

    #[test]
    fn boot_slews_below_the_boot_threshold() {
        let p = Policy::default();
        let m = meas(-50 * NS_PER_MS, NS_PER_MS, false);
        assert_eq!(decide(&m, Phase::Boot, &p), Action::Slew(-50 * NS_PER_MS));
    }

    #[test]
    fn steady_steps_only_above_the_step_threshold() {
        let p = Policy::default();
        let slow = meas(-800 * NS_PER_MS, NS_PER_MS, false);
        assert_eq!(
            decide(&slow, Phase::Steady, &p),
            Action::Step(-800 * NS_PER_MS)
        );
        let small = meas(400 * NS_PER_MS, NS_PER_MS, false);
        assert_eq!(
            decide(&small, Phase::Steady, &p),
            Action::Slew(400 * NS_PER_MS)
        );
    }

    #[test]
    fn uncertainty_is_subtracted_before_stepping() {
        let p = Policy::default();
        // 600 ms offset but 150 ms uncertainty: the true offset could be
        // 450 ms, under the 500 ms steady threshold, so slew.
        let m = meas(600 * NS_PER_MS, 150 * NS_PER_MS, false);
        assert_eq!(decide(&m, Phase::Steady, &p), Action::Slew(600 * NS_PER_MS));
        // With a tight bound the same offset steps.
        let m = meas(600 * NS_PER_MS, 50 * NS_PER_MS, false);
        assert_eq!(decide(&m, Phase::Steady, &p), Action::Step(600 * NS_PER_MS));
    }

    #[test]
    fn threshold_is_exclusive() {
        let p = Policy::default();
        let m = meas(p.step_threshold_ns, 0, false);
        assert_eq!(
            decide(&m, Phase::Steady, &p),
            Action::Slew(p.step_threshold_ns)
        );
        let m = meas(p.step_threshold_ns + 1, 0, false);
        assert_eq!(
            decide(&m, Phase::Steady, &p),
            Action::Step(p.step_threshold_ns + 1)
        );
    }

    #[test]
    fn coarse_readings_step_only_on_large_offsets_and_never_slew() {
        let p = Policy::default();
        let small = meas(1500 * NS_PER_MS, 500 * NS_PER_MS, true);
        assert_eq!(decide(&small, Phase::Boot, &p), Action::Hold);
        assert_eq!(decide(&small, Phase::Steady, &p), Action::Hold);
        let large = meas(-10 * NS_PER_SEC, 500 * NS_PER_MS, true);
        assert_eq!(
            decide(&large, Phase::Boot, &p),
            Action::Step(-10 * NS_PER_SEC)
        );
        assert_eq!(
            decide(&large, Phase::Steady, &p),
            Action::Step(-10 * NS_PER_SEC)
        );
    }

    #[test]
    fn extreme_offsets_do_not_overflow() {
        let p = Policy::default();
        let m = meas(i64::MIN, 0, false);
        assert_eq!(decide(&m, Phase::Steady, &p), Action::Step(i64::MIN));
    }

    #[test]
    fn time_constant_tracks_the_poll_interval() {
        assert_eq!(pll_time_constant(0), 0);
        assert_eq!(pll_time_constant(1), 0);
        assert_eq!(pll_time_constant(16), 4);
        assert_eq!(pll_time_constant(60), 6);
        assert_eq!(pll_time_constant(64), 6);
        assert_eq!(pll_time_constant(100), 7);
        assert_eq!(pll_time_constant(1 << 20), 10);
    }

    #[test]
    fn split_delta_keeps_nanoseconds_non_negative() {
        assert_eq!(split_delta(0), (0, 0));
        assert_eq!(split_delta(1_500_000_000), (1, 500_000_000));
        assert_eq!(split_delta(-1), (-1, 999_999_999));
        assert_eq!(split_delta(-1_500_000_000), (-2, 500_000_000));
        assert_eq!(split_delta(-2_000_000_000), (-2, 0));
        for d in [-3_000_000_001i64, -999_999_999, 7, 42_000_000_123] {
            let (s, n) = split_delta(d);
            assert!((0..NS_PER_SEC).contains(&n));
            assert_eq!(s * NS_PER_SEC + n, d);
        }
    }
}
