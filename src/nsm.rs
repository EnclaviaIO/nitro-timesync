//! Attestation documents from this enclave's own /dev/nsm, behind a trait
//! so the sync loop can be tested with canned documents.

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

pub const NSM_DEVICE: &str = "/dev/nsm";

pub trait AttestationSource {
    /// Request a fresh attestation document and return its raw bytes.
    fn attest(&mut self) -> Result<Vec<u8>, String>;
}

/// The NSM driver. The fd is opened lazily and dropped after any error, so
/// a transient driver fault is retried on a fresh fd.
#[derive(Default)]
pub struct Nsm {
    fd: Option<i32>,
}

impl Nsm {
    fn close(&mut self) {
        if let Some(fd) = self.fd.take() {
            nsm_exit(fd);
        }
    }
}

impl Drop for Nsm {
    fn drop(&mut self) {
        self.close();
    }
}

impl AttestationSource for Nsm {
    fn attest(&mut self) -> Result<Vec<u8>, String> {
        let fd = match self.fd {
            Some(fd) => fd,
            None => {
                let fd = nsm_init();
                if fd < 0 {
                    return Err(format!("cannot open {NSM_DEVICE}"));
                }
                self.fd = Some(fd);
                fd
            }
        };
        // No nonce, user data or public key: the document binds nothing
        // and is only read for its timestamp.
        let request = Request::Attestation {
            user_data: None,
            nonce: None,
            public_key: None,
        };
        match nsm_process_request(fd, request) {
            Response::Attestation { document } => Ok(document),
            Response::Error(e) => {
                self.close();
                Err(format!("NSM attestation error: {e:?}"))
            }
            other => {
                self.close();
                Err(format!("NSM attestation unexpected response: {other:?}"))
            }
        }
    }
}
