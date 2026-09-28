//! Keep an AWS Nitro Enclave's `CLOCK_REALTIME` on the Nitro hypervisor's
//! time, using the `timestamp` of attestation documents from the enclave's
//! own `/dev/nsm`.
//!
//! The library holds the parts that do not need an enclave, so they can be
//! unit-tested anywhere:
//!
//! * [`decision`]: offset math (round-trip midpoint, resolution, sanity
//!   bounds) and the step / slew / hold decision;
//! * [`doc`]: minimal decode of an attestation document's `timestamp`;
//! * [`sync`]: one synchronisation round over the [`nsm::AttestationSource`]
//!   and [`clock::Clock`] traits;
//! * [`clock`] and [`nsm`]: the real kernel clock (`adjtimex`) and NSM
//!   driver behind those traits.

pub mod clock;
pub mod decision;
pub mod doc;
pub mod nsm;
pub mod sync;
