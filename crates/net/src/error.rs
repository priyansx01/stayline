#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("wintun.dll could not be loaded from {path}: {reason}")]
    WintunMissing { path: String, reason: String },

    #[error("Wintun: {0} (are you running as administrator?)")]
    Wintun(String),

    #[error("{call} failed with Windows error {code}")]
    Win32 { call: &'static str, code: u32 },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T, E = NetError> = std::result::Result<T, E>;

pub(crate) fn check(
    call: &'static str,
    err: windows::Win32::Foundation::WIN32_ERROR,
) -> Result<()> {
    tracing::debug!(call, code = err.0, "IP Helper call");
    if err.is_ok() {
        Ok(())
    } else {
        Err(NetError::Win32 { call, code: err.0 })
    }
}
