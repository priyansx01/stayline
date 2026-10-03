//! Starting the stayline service from the app when it is installed but
//! stopped. The installer lets interactive users start (only start) it.

use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST, WIN32_ERROR,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT, SERVICE_START,
    StartServiceW,
};
use windows::core::w;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartError {
    NotInstalled,
    AccessDenied,
    Failed(u32),
}

fn code(e: &windows::core::Error) -> WIN32_ERROR {
    WIN32_ERROR::from_error(e).unwrap_or(WIN32_ERROR(0))
}

/// Asks Windows to start the service. Already running counts as success.
pub fn start() -> Result<(), StartError> {
    // SAFETY: plain service-manager calls; every handle opened here is closed.
    unsafe {
        let manager = OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
            .map_err(|e| StartError::Failed(code(&e).0))?;
        let result = match OpenServiceW(manager, w!("stayline"), SERVICE_START) {
            Ok(service) => {
                let started = StartServiceW(service, None);
                let _ = CloseServiceHandle(service);
                match started {
                    Ok(()) => Ok(()),
                    Err(e) if code(&e) == ERROR_SERVICE_ALREADY_RUNNING => Ok(()),
                    Err(e) if code(&e) == ERROR_ACCESS_DENIED => Err(StartError::AccessDenied),
                    Err(e) => Err(StartError::Failed(code(&e).0)),
                }
            }
            Err(e) if code(&e) == ERROR_SERVICE_DOES_NOT_EXIST => Err(StartError::NotInstalled),
            Err(e) if code(&e) == ERROR_ACCESS_DENIED => Err(StartError::AccessDenied),
            Err(e) => Err(StartError::Failed(code(&e).0)),
        };
        let _ = CloseServiceHandle(manager);
        result
    }
}
