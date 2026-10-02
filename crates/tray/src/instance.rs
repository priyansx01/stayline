//! One tray per Windows session. Starting stayline again brings up the
//! running instance's window instead of adding a second tray icon.

use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
use windows::Win32::System::Threading::{
    CreateEventW, CreateMutexW, INFINITE, SetEvent, WaitForSingleObject,
};
use windows::core::w;

/// Signalled by later launches to ask this instance to show its window.
pub struct ShowRequests(HANDLE);

// SAFETY: an event handle may be waited on from any thread.
unsafe impl Send for ShowRequests {}

/// Becomes the running instance, or (if one exists) asks it to show its
/// window and returns `None`.
pub fn claim() -> Option<ShowRequests> {
    // SAFETY: plain Win32 calls; both handles stay open for the life of the
    // process on purpose.
    unsafe {
        let event = CreateEventW(None, false, false, w!("Local\\stayline-show")).ok()?;
        let mutex = CreateMutexW(None, true, w!("Local\\stayline-tray"));
        if mutex.is_err() || GetLastError() == ERROR_ALREADY_EXISTS {
            let _ = SetEvent(event);
            return None;
        }
        Some(ShowRequests(event))
    }
}

/// Calls `show` (on a background thread) whenever another launch asks.
pub fn on_show_request(requests: ShowRequests, show: impl Fn() + Send + 'static) {
    let spawned = std::thread::Builder::new()
        .name("show-requests".into())
        .spawn(move || {
            let requests = requests;
            loop {
                // SAFETY: the handle is valid for the life of the process.
                unsafe { WaitForSingleObject(requests.0, INFINITE) };
                show();
            }
        });
    if let Err(e) = spawned {
        tracing::warn!(error = %e, "cannot listen for show requests");
    }
}
