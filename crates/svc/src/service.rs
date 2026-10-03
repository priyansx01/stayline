//! Windows service entry point, install and uninstall.

use std::ffi::OsString;
use std::time::Duration;

use anyhow::{Context, Result};
use stayline_core::supervisor::NetEvent;
use tokio::sync::watch;
use windows_service::service::{
    PowerEventParam, ServiceAccess, ServiceAction, ServiceActionType, ServiceControl,
    ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::controller::Controller;

pub const SERVICE_NAME: &str = "stayline";
const DISPLAY_NAME: &str = "Stayline VPN";
const DESCRIPTION: &str =
    "Keeps the Stayline VPN tunnel connected and reconnects it after network changes and sleep.";

define_windows_service!(ffi_service_main, service_main);

/// Hands the process to the service control manager. Only works when
/// started as a service.
pub fn dispatch() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).context("not started as a service")
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!(error = format!("{e:#}"), "service failed");
    }
}

fn run_service() -> Result<()> {
    let controller = Controller::new();
    let (stop_tx, stop_rx) = watch::channel(false);

    let handler_controller = controller.clone();
    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = stop_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::PowerEvent(
                PowerEventParam::ResumeAutomatic | PowerEventParam::ResumeSuspend,
            ) => {
                tracing::info!("resumed from sleep");
                handler_controller.notify(NetEvent::Resumed);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::PowerEvent(_) | ServiceControl::Interrogate => {
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;

    let set_state = |state: ServiceState, accept: ServiceControlAccept, wait: Duration| {
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: wait,
            process_id: None,
        })
    };
    set_state(
        ServiceState::Running,
        ServiceControlAccept::STOP
            | ServiceControlAccept::SHUTDOWN
            | ServiceControlAccept::POWER_EVENT,
        Duration::ZERO,
    )?;
    tracing::info!("service running");
    if let Err(e) = allow_users_to_start() {
        tracing::warn!(error = %e, "could not let users start the service");
    }

    let result = crate::run(controller, stop_rx);

    set_state(
        ServiceState::StopPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(5),
    )?;
    set_state(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        Duration::ZERO,
    )?;
    tracing::info!("service stopped");
    result
}

/// Registers the service (auto start, LocalSystem, restart on crash) and starts it.
pub fn install() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("could not open the service manager (run as administrator)")?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("could not create the service (already installed?)")?;
    service.set_description(DESCRIPTION)?;
    let restart = |secs| ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(secs),
    };
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart(5), restart(30), restart(60)]),
    })?;
    service
        .start::<&str>(&[])
        .context("service created but did not start")?;
    println!("installed and started the '{SERVICE_NAME}' service");
    Ok(())
}

/// Stops and removes the service.
pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("could not open the service manager (run as administrator)")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("service is not installed")?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
        for _ in 0..50 {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    service.delete()?;
    println!("removed the '{SERVICE_NAME}' service");
    Ok(())
}

/// Lets interactively signed-in users start (and query) the service, so the
/// app can start it again if it was stopped. Nothing else is granted.
fn allow_users_to_start() -> windows::core::Result<()> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT, SERVICE_ALL_ACCESS,
        SetServiceObjectSecurity,
    };
    use windows::core::{HSTRING, w};

    // The default service DACL, with SERVICE_START (RP) added for
    // interactive users (IU).
    const SDDL: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

    // SAFETY: handles and the descriptor are released before returning.
    unsafe {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(SDDL),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )?;
        let result = (|| {
            let manager = OpenSCManagerW(None, None, SC_MANAGER_CONNECT)?;
            let service = OpenServiceW(manager, w!("stayline"), SERVICE_ALL_ACCESS);
            let set = service
                .as_ref()
                .map_err(Clone::clone)
                .and_then(|s| SetServiceObjectSecurity(*s, DACL_SECURITY_INFORMATION, descriptor));
            if let Ok(service) = service {
                let _ = CloseServiceHandle(service);
            }
            let _ = CloseServiceHandle(manager);
            set
        })();
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        result
    }
}
