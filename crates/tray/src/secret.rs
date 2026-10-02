//! The saved password, encrypted with Windows DPAPI for the current user.
//!
//! Only the same Windows account on the same machine can decrypt it. The
//! file lives in the user's local (non-roaming) app data folder.

use std::path::PathBuf;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows::core::w;
use zeroize::Zeroizing;

/// Extra input to DPAPI so other programs using DPAPI for this user cannot
/// decrypt the file by accident.
const ENTROPY: &[u8] = b"stayline-credential-v1";

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("no user profile directory")]
    NoHome,
    #[error("could not read or write the saved password: {0}")]
    Io(#[from] std::io::Error),
    #[error("the saved password could not be decrypted: {0}")]
    Crypto(windows::core::Error),
    #[error("the saved password is corrupt")]
    Corrupt,
}

pub fn path() -> Result<PathBuf, SecretError> {
    let dirs = directories::ProjectDirs::from("", "", "stayline").ok_or(SecretError::NoHome)?;
    Ok(dirs.data_local_dir().join("credential.bin"))
}

pub fn save(password: &str) -> Result<(), SecretError> {
    let path = path()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let sealed = protect(password.as_bytes())?;
    crate::settings::write_atomically(&path, &sealed)?;
    Ok(())
}

/// The saved password, or `None` if none is saved.
pub fn load() -> Result<Option<Zeroizing<String>>, SecretError> {
    let sealed = match std::fs::read(path()?) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let plain = unprotect(&sealed)?;
    let text = std::str::from_utf8(&plain).map_err(|_| SecretError::Corrupt)?;
    Ok(Some(Zeroizing::new(text.to_owned())))
}

pub fn forget() -> Result<(), SecretError> {
    match std::fs::remove_file(path()?) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

pub fn is_saved() -> bool {
    path().is_ok_and(|p| p.exists())
}

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr().cast_mut(),
    }
}

/// Copies a DPAPI output blob and frees it.
///
/// # Safety
/// `out` must have been filled by a successful DPAPI call.
unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Zeroizing<Vec<u8>> {
    // SAFETY: DPAPI returned a LocalAlloc'd buffer of cbData bytes.
    unsafe {
        let data =
            Zeroizing::new(std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec());
        std::ptr::write_bytes(out.pbData, 0, out.cbData as usize);
        let _ = LocalFree(Some(HLOCAL(out.pbData.cast())));
        data
    }
}

pub(crate) fn protect(plain: &[u8]) -> Result<Vec<u8>, SecretError> {
    let input = blob(plain);
    let entropy = blob(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input and entropy point to live buffers; out receives a
    // LocalAlloc'd buffer that take() frees.
    unsafe {
        CryptProtectData(
            &input,
            w!("stayline"),
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
        .map_err(SecretError::Crypto)?;
        Ok(take(out).to_vec())
    }
}

pub(crate) fn unprotect(sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let input = blob(sealed);
    let entropy = blob(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: as in protect().
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
        .map_err(SecretError::Crypto)?;
        Ok(take(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_is_not_plaintext() {
        let sealed = protect(b"correct horse battery staple").unwrap();
        assert!(!sealed.windows(7).any(|w| w == b"correct"));
        assert_eq!(
            &unprotect(&sealed).unwrap()[..],
            b"correct horse battery staple"
        );
    }

    #[test]
    fn tampered_data_fails_cleanly() {
        let mut sealed = protect(b"secret").unwrap();
        let mid = sealed.len() / 2;
        sealed[mid] ^= 0xff;
        assert!(matches!(unprotect(&sealed), Err(SecretError::Crypto(_))));
    }

    #[test]
    fn garbage_fails_cleanly() {
        assert!(unprotect(b"not a dpapi blob").is_err());
    }
}
