//! Saved passwords, one per connection, encrypted with Windows DPAPI for
//! the current user. Only the same Windows account on the same machine can
//! decrypt them. Files live in the user's local (non-roaming) app data.

use std::path::PathBuf;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows::core::w;
use zeroize::Zeroizing;

use crate::{project_dirs, write_atomically};

/// Extra input to DPAPI so other programs using DPAPI for this user cannot
/// decrypt the files by accident.
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

fn dir() -> Result<PathBuf, SecretError> {
    Ok(project_dirs()
        .map_err(|_| SecretError::NoHome)?
        .data_local_dir()
        .join("credentials"))
}

/// File for a connection: readable name plus a hash, so different names
/// never share a file.
pub fn path(connection: &str) -> Result<PathBuf, SecretError> {
    let readable: String = connection
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(40)
        .collect();
    Ok(dir()?.join(format!(
        "{readable}-{:016x}.bin",
        fnv1a(connection.as_bytes())
    )))
}

fn fnv1a(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

pub fn save(connection: &str, password: &str) -> Result<(), SecretError> {
    let sealed = protect(password.as_bytes())?;
    write_atomically(&path(connection)?, &sealed)?;
    Ok(())
}

/// The saved password, or `None` if none is saved.
pub fn load(connection: &str) -> Result<Option<Zeroizing<String>>, SecretError> {
    let sealed = match std::fs::read(path(connection)?) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let plain = unprotect(&sealed)?;
    let text = std::str::from_utf8(&plain).map_err(|_| SecretError::Corrupt)?;
    Ok(Some(Zeroizing::new(text.to_owned())))
}

pub fn forget(connection: &str) -> Result<(), SecretError> {
    match std::fs::remove_file(path(connection)?) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

pub fn is_saved(connection: &str) -> bool {
    path(connection).is_ok_and(|p| p.exists())
}

/// Keeps a saved password when a connection is renamed.
pub fn rename(old: &str, new: &str) -> Result<(), SecretError> {
    let (from, to) = (path(old)?, path(new)?);
    if from.exists() && from != to {
        std::fs::rename(from, to)?;
    }
    Ok(())
}

/// Moves the password saved before multiple connections existed to the
/// connection it was converted into.
pub(crate) fn adopt_legacy(connection: &str) {
    let Ok(dirs) = project_dirs() else { return };
    let legacy = dirs.data_local_dir().join("credential.bin");
    let Ok(target) = path(connection) else { return };
    if legacy.exists() && !target.exists() {
        let moved = target
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| std::fs::rename(&legacy, &target));
        if let Err(e) = moved {
            tracing::warn!(error = %e, "could not move the saved password");
        }
    }
}

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr().cast_mut(),
    }
}

/// Copies a DPAPI output blob, wipes and frees it.
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

fn protect(plain: &[u8]) -> Result<Vec<u8>, SecretError> {
    let input = blob(plain);
    let entropy = blob(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input and entropy point to live buffers; take() frees out.
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

fn unprotect(sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretError> {
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
        assert!(unprotect(b"not a dpapi blob").is_err());
    }

    #[test]
    fn file_names_are_distinct_and_safe() {
        let a = path("Company VPN").unwrap();
        let b = path("company-vpn").unwrap();
        assert_ne!(a, b);
        let name = a.file_name().unwrap().to_str().unwrap();
        assert!(
            name.starts_with("company-vpn-") && name.ends_with(".bin"),
            "{name}"
        );
        let odd = path("../..\\x:y").unwrap();
        assert_eq!(odd.parent(), a.parent());
    }
}
