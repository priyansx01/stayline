//! User-side storage shared by the tray app and developer tools: the
//! connection settings and the optionally saved password.

pub mod format;
pub mod settings;

#[cfg(windows)]
pub mod secret;
