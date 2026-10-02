//! Access control for the service's pipe.

use std::ffi::c_void;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::core::w;

/// Security attributes for the pipe: full access for SYSTEM and
/// administrators, read/write for interactively logged-on users, nobody
/// else (including network logons).
pub struct PipeSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

// SAFETY: the descriptor is immutable after creation and owned by this value.
unsafe impl Send for PipeSecurity {}
unsafe impl Sync for PipeSecurity {}

impl PipeSecurity {
    pub fn new() -> std::io::Result<Self> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // D:P = protected DACL; SY/BA = SYSTEM/Administrators get all access;
        // IU = interactive users get generic read and write.
        // SAFETY: the SDDL string is a valid NUL-terminated literal.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(std::io::Error::other)?;
        Ok(Self {
            descriptor,
            attributes: SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: false.into(),
            },
        })
    }

    /// Pointer for `ServerOptions::create_with_security_attributes_raw`.
    /// Valid while `self` lives.
    pub fn as_ptr(&self) -> *mut c_void {
        (&raw const self.attributes).cast_mut().cast()
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by
        // ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
        }
    }
}
