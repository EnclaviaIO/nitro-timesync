//! The kernel clock, behind a trait so the sync loop can be tested with a
//! fake.
//!
//! Both operations go through `adjtimex(2)` on CLOCK_REALTIME and need
//! CAP_SYS_TIME. Neither touches CLOCK_MONOTONIC: a step moves only the
//! wall clock, and the PLL's frequency correction is applied to the
//! shared timekeeping multiplier, which also makes monotonic time run at
//! the corrected rate but never jumps it.

use std::io;

use crate::decision::{split_delta, NS_PER_SEC};

/// Kernel PLL state reported after a slew.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PllState {
    /// Frequency correction the kernel is applying, in ppm.
    pub freq_ppm: f64,
}

pub trait Clock {
    /// Current CLOCK_REALTIME, ns since the epoch.
    fn realtime_ns(&self) -> i64;

    /// Jump CLOCK_REALTIME by `delta_ns`. With `pll_time_constant`, also
    /// (re)enable the kernel PLL and restart its phase tracking from the
    /// new time, keeping its learned frequency; without it, leave the PLL
    /// alone.
    fn step(&mut self, delta_ns: i64, pll_time_constant: Option<i64>) -> io::Result<()>;

    /// Feed `offset_ns` to the kernel PLL, which slews the clock towards
    /// it and adjusts the frequency so the drift itself shrinks.
    fn slew(&mut self, offset_ns: i64, time_constant: i64) -> io::Result<PllState>;
}

/// The kernel clamps a single PLL offset to MAXPHASE; clamp before the
/// cast so an out-of-range value never reaches the syscall.
const MAXPHASE_NS: i64 = 500_000_000;

/// Status bits written on every call.
///
/// STA_PLL enables the kernel's phase-locked loop. STA_UNSYNC is kept set
/// on purpose: while it is clear, kernels built with GENERIC_CMOS_UPDATE
/// or RTC_SYSTOHC write the system time to the hardware RTC every 11
/// minutes, and an enclave has no RTC worth writing. It does not affect
/// the PLL.
const STATUS: libc::c_int = libc::STA_PLL | libc::STA_UNSYNC | libc::STA_NANO;

pub struct KernelClock;

impl KernelClock {
    fn adjtimex(tx: &mut libc::timex) -> io::Result<libc::c_int> {
        // SAFETY: `tx` is a valid, exclusively borrowed timex.
        let rc = unsafe { libc::adjtimex(tx) };
        // A non-negative return is the clock state (TIME_OK, TIME_ERROR,
        // ...), not an error; TIME_ERROR is expected while STA_UNSYNC is set.
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc)
        }
    }

    fn pll_request(time_constant: i64) -> libc::timex {
        // SAFETY: timex is a plain C struct for which all-zero is valid.
        let mut tx: libc::timex = unsafe { std::mem::zeroed() };
        // ADJ_NANO makes `offset` nanoseconds. It also affects
        // `constant`: the kernel applies the nano flag before the time
        // constant, and only outside nano mode does it add 4 to it.
        tx.modes = libc::ADJ_OFFSET | libc::ADJ_STATUS | libc::ADJ_TIMECONST | libc::ADJ_NANO;
        tx.status = STATUS;
        tx.constant = time_constant as libc::c_long;
        tx
    }
}

impl Clock for KernelClock {
    fn realtime_ns(&self) -> i64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid out-pointer. CLOCK_REALTIME always exists.
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
        ts.tv_sec
            .saturating_mul(NS_PER_SEC)
            .saturating_add(ts.tv_nsec)
    }

    fn step(&mut self, delta_ns: i64, pll_time_constant: Option<i64>) -> io::Result<()> {
        // ADJ_SETOFFSET adds the delta atomically inside the kernel, so no
        // time passes between reading and writing the clock as it would
        // with clock_gettime + clock_settime.
        let mut tx = match pll_time_constant {
            // In the same call, a zero ADJ_OFFSET clears the PLL's pending
            // phase correction and resets its reference time; the kernel
            // applies the step before the PLL update, so the reference is
            // taken on the new timescale.
            Some(tc) => Self::pll_request(tc),
            // ADJ_NANO only sets the unit of `time.tv_usec`; the PLL is not
            // enabled or fed.
            None => {
                // SAFETY: timex is a plain C struct for which all-zero is valid.
                let mut tx: libc::timex = unsafe { std::mem::zeroed() };
                tx.modes = libc::ADJ_NANO;
                tx
            }
        };
        tx.modes |= libc::ADJ_SETOFFSET;
        tx.offset = 0;
        let (sec, nsec) = split_delta(delta_ns);
        tx.time.tv_sec = sec as libc::time_t;
        tx.time.tv_usec = nsec as libc::suseconds_t;
        Self::adjtimex(&mut tx).map(|_| ())
    }

    fn slew(&mut self, offset_ns: i64, time_constant: i64) -> io::Result<PllState> {
        let mut tx = Self::pll_request(time_constant);
        tx.offset = offset_ns.clamp(-MAXPHASE_NS, MAXPHASE_NS) as libc::c_long;
        Self::adjtimex(&mut tx)?;
        // `freq` is reported in ppm with a 16-bit binary fraction.
        Ok(PllState {
            freq_ppm: tx.freq as f64 / 65536.0,
        })
    }
}
