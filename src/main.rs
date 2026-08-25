#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(not(target_os = "windows"))]
compile_error!("Audio Fade Fixer only supports Windows.");

use audio_fade_fixer::registry;
use native_windows_gui as nwg;
use std::{
    cell::{Cell, RefCell},
    env, io, mem,
    os::windows::ffi::OsStrExt,
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};
use winapi::{
    shared::minwindef::FALSE,
    um::{
        handleapi::CloseHandle,
        processthreadsapi::GetExitCodeProcess,
        shellapi::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW},
        synchapi::WaitForSingleObject,
        winbase::{INFINITE, WAIT_FAILED},
        winuser::SW_HIDE,
    },
};

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn quote_windows_arg(value: &std::ffi::OsStr) -> String {
    let value = value.to_string_lossy();
    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for character in value.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                quoted.push(character);
            }
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

fn operation_nonce() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "{:016x}{:08x}{:08x}",
        now.as_secs(),
        now.subsec_nanos(),
        std::process::id()
    )
}

fn run_elevated_helper(
    operation: &str,
    backup: Option<&Path>,
    fingerprint: Option<&str>,
) -> io::Result<registry::OperationReport> {
    if !matches!(operation, "apply" | "restore") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid helper operation",
        ));
    }
    let nonce = operation_nonce();
    let executable = env::current_exe()?;
    let mut arguments = format!("--elevated-helper --operation {operation} --nonce {nonce}");
    if let Some(path) = backup {
        arguments.push_str(" --backup ");
        arguments.push_str(&quote_windows_arg(path.as_os_str()));
    }
    if let Some(value) = fingerprint {
        arguments.push_str(" --fingerprint ");
        arguments.push_str(value);
    }
    let executable_wide = wide(executable.as_os_str());
    let arguments_wide = wide(arguments.as_ref());
    let verb_wide = wide(std::ffi::OsStr::new("runas"));
    // SAFETY: SHELLEXECUTEINFOW is a C-compatible POD structure whose documented
    // initialization begins with zeroing followed by cbSize and required fields.
    let mut info: SHELLEXECUTEINFOW = unsafe { mem::zeroed() };
    info.cbSize = mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb_wide.as_ptr();
    info.lpFile = executable_wide.as_ptr();
    info.lpParameters = arguments_wide.as_ptr();
    info.nShow = SW_HIDE;
    // SAFETY: all UTF-16 buffers are NUL-terminated and remain alive through the
    // synchronous call; `info` has the documented size and initialized fields.
    let launched = unsafe { ShellExecuteExW(&mut info) };
    if launched == FALSE {
        return Err(io::Error::last_os_error());
    }
    if info.hProcess.is_null() {
        return Err(io::Error::other(
            "Windows did not return an elevated helper process",
        ));
    }
    // SAFETY: a non-null process handle returned by ShellExecuteExW is valid for
    // waiting until it is closed below.
    let wait = unsafe { WaitForSingleObject(info.hProcess, INFINITE) };
    if wait == WAIT_FAILED {
        let error = io::Error::last_os_error();
        // SAFETY: the owned process handle is closed exactly once on this branch.
        unsafe { CloseHandle(info.hProcess) };
        return Err(error);
    }
    let mut exit_code = 0;
    // SAFETY: the process has signaled and `exit_code` is a valid out pointer.
    let got_exit = unsafe { GetExitCodeProcess(info.hProcess, &mut exit_code) };
    // SAFETY: the owned process handle is closed exactly once on this branch.
    unsafe { CloseHandle(info.hProcess) };
    if got_exit == FALSE {
        return Err(io::Error::last_os_error());
    }
    let report = registry::read_operation_report(&nonce)?;
    if exit_code != 0 && report.success {
        return Err(io::Error::other(format!(
            "Elevated helper exited with unexpected status {exit_code}"
        )));
    }
    Ok(report)
}

fn run_helper_mode(arguments: &[String]) -> i32 {
    let parsed = match arguments {
        [_, helper, operation_flag, operation, nonce_flag, nonce]
            if helper == "--elevated-helper"
                && operation_flag == "--operation"
                && operation == "apply"
                && nonce_flag == "--nonce" =>
        {
            Some((operation.as_str(), nonce.as_str(), None))
        }
        [
            _,
            helper,
            operation_flag,
            operation,
            nonce_flag,
            nonce,
            backup_flag,
            backup,
            fingerprint_flag,
            fingerprint,
        ] if helper == "--elevated-helper"
            && operation_flag == "--operation"
            && operation == "restore"
            && nonce_flag == "--nonce"
            && backup_flag == "--backup"
            && fingerprint_flag == "--fingerprint" =>
        {
            Some((
                operation.as_str(),
                nonce.as_str(),
                Some((backup.as_str(), fingerprint.as_str())),
            ))
        }
        _ => None,
    };
    let Some((operation, nonce, backup)) = parsed else {
        return 2;
    };
    if registry::operation_report_path(nonce).is_err() {
        return 2;
    }
    let result = registry::harden_storage_permissions().and_then(|()| match operation {
        "apply" => registry::apply_all(),
        "restore" => backup
            .map(|(path, fingerprint)| (Path::new(path), fingerprint))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Restore requires --backup"))
            .and_then(|(path, fingerprint)| {
                registry::restore_file_with_fingerprint(path, fingerprint)
            }),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid helper arguments",
        )),
    });
    let (report, code) = match result {
        Ok(report) => {
            let code = if report.success { 0 } else { 1 };
            (report, code)
        }
        Err(error) => (
            registry::OperationReport {
                success: false,
                summary: error.to_string(),
                file: None,
                lines: vec![format!(
                    "Elevated helper rejected or failed the operation: {error}"
                )],
            },
            1,
        ),
    };
    if registry::write_operation_report(nonce, &report).is_err() {
        3
    } else {
        code
    }
}

struct App {
    icon: nwg::Icon,
    window: nwg::Window,
    heading: nwg::Label,
    intro: nwg::Label,
    devices: nwg::ListBox<String>,
    scan: nwg::Button,
    fix: nwg::Button,
    restore: nwg::Button,
    restore_file: nwg::Button,
    advanced: nwg::Button,
    status: nwg::Label,
    warning: nwg::Label,
    log_label: nwg::Label,
    log: nwg::TextBox,
    file_dialog: nwg::FileDialog,
    found: RefCell<Vec<registry::Device>>,
    advanced_open: Cell<bool>,
}

impl App {
    fn build() -> Result<Rc<Self>, nwg::NwgError> {
        let mut app = App {
            icon: Default::default(),
            window: Default::default(),
            heading: Default::default(),
            intro: Default::default(),
            devices: Default::default(),
            scan: Default::default(),
            fix: Default::default(),
            restore: Default::default(),
            restore_file: Default::default(),
            advanced: Default::default(),
            status: Default::default(),
            warning: Default::default(),
            log_label: Default::default(),
            log: Default::default(),
            file_dialog: Default::default(),
            found: RefCell::new(Vec::new()),
            advanced_open: Cell::new(false),
        };
        let resources = nwg::EmbedResource::load(None)?;
        app.icon = resources.icon(1, None).ok_or_else(|| {
            nwg::NwgError::resource_create("Embedded application icon #1 could not be loaded")
        })?;
        nwg::Window::builder()
            .size((650, 405))
            .position((300, 180))
            .title("Audio Fade Fixer")
            .icon(Some(&app.icon))
            .flags(nwg::WindowFlags::WINDOW | nwg::WindowFlags::VISIBLE)
            .build(&mut app.window)?;
        nwg::Label::builder()
            .text("Audio Fade Fixer")
            .position((18, 12))
            .size((600, 24))
            .parent(&app.window)
            .build(&mut app.heading)?;
        nwg::Label::builder().text("Find and disable Realtek audio idle power settings that can cause fade-in after silence.")
            .position((18, 39)).size((610, 24)).parent(&app.window).build(&mut app.intro)?;
        nwg::ListBox::builder()
            .position((18, 68))
            .size((610, 185))
            .parent(&app.window)
            .focus(true)
            .build(&mut app.devices)?;
        nwg::Button::builder()
            .text("Scan")
            .position((18, 265))
            .size((75, 30))
            .parent(&app.window)
            .build(&mut app.scan)?;
        nwg::Button::builder()
            .text("Back up + fix")
            .position((101, 265))
            .size((115, 30))
            .parent(&app.window)
            .build(&mut app.fix)?;
        nwg::Button::builder()
            .text("Restore latest")
            .position((224, 265))
            .size((105, 30))
            .parent(&app.window)
            .build(&mut app.restore)?;
        nwg::Button::builder()
            .text("Choose backup...")
            .position((337, 265))
            .size((125, 30))
            .parent(&app.window)
            .build(&mut app.restore_file)?;
        nwg::Button::builder()
            .text("Advanced v")
            .position((506, 265))
            .size((122, 30))
            .parent(&app.window)
            .build(&mut app.advanced)?;
        nwg::Label::builder()
            .text("Ready.")
            .position((18, 306))
            .size((610, 24))
            .parent(&app.window)
            .build(&mut app.status)?;
        nwg::Label::builder().text("No warranty. Registry changes carry risk; you assume all risk. Reboot after applying or restoring.")
            .position((18, 337)).size((610, 38)).parent(&app.window).build(&mut app.warning)?;
        nwg::Label::builder()
            .text("Operation log")
            .position((18, 387))
            .size((610, 22))
            .parent(&app.window)
            .build(&mut app.log_label)?;
        nwg::TextBox::builder()
            .text("")
            .position((18, 414))
            .size((610, 190))
            .readonly(true)
            .limit(200_000)
            .parent(&app.window)
            .build(&mut app.log)?;
        app.log_label.set_visible(false);
        app.log.set_visible(false);
        nwg::FileDialog::builder()
            .title("Choose an Audio Fade Fixer backup")
            .action(nwg::FileDialogAction::Open)
            .multiselect(false)
            .filters("Audio Fade Fixer backup (*.json)|JSON file (*.json)")
            .build(&mut app.file_dialog)?;

        let app = Rc::new(app);
        let ui = app.clone();
        let handle = app.window.handle;
        nwg::full_bind_event_handler(&handle, move |event, _data, event_handle| {
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                if event == nwg::Event::OnWindowClose && event_handle == ui.window.handle {
                    nwg::stop_thread_dispatch();
                }
                if event == nwg::Event::OnButtonClick && event_handle == ui.scan.handle {
                    ui.do_scan();
                }
                if event == nwg::Event::OnButtonClick && event_handle == ui.fix.handle {
                    ui.do_fix();
                }
                if event == nwg::Event::OnButtonClick && event_handle == ui.restore.handle {
                    ui.confirm_restore(None);
                }
                if event == nwg::Event::OnButtonClick && event_handle == ui.restore_file.handle {
                    ui.choose_restore();
                }
                if event == nwg::Event::OnButtonClick && event_handle == ui.advanced.handle {
                    ui.toggle_advanced();
                }
            }));
            if result.is_err() {
                ui.append_log(
                    "SECURITY: An unexpected UI error was caught; the process was kept alive.",
                );
                ui.status
                    .set_text("Unexpected UI error caught. No further changes were made.");
            }
        });
        app.append_log("Application started without elevation. UAC is requested only for confirmed registry writes.");
        app.do_scan();
        Ok(app)
    }

    fn append_log(&self, message: &str) {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
            % 86_400;
        let stamp = format!(
            "{:02}:{:02}:{:02}Z",
            seconds / 3600,
            (seconds / 60) % 60,
            seconds % 60
        );
        let clean = message.replace(['\r', '\n'], " ");
        let existing = self.log.text();
        self.log
            .set_text(&format!("{existing}[{stamp}] {clean}\r\n"));
        self.log.scroll_lastline();
    }

    fn append_lines(&self, lines: &[String]) {
        for line in lines {
            self.append_log(line);
        }
    }

    fn do_scan(&self) {
        self.append_log(r"Scanning HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}...");
        match registry::scan() {
            Ok(report) => {
                self.append_log(&format!(
                    "Examined {} numbered audio driver key(s).",
                    report.examined
                ));
                for warning in &report.warnings {
                    self.append_log(&format!("SCAN WARNING: {warning}"));
                }
                for device in &report.devices {
                    self.append_log(&format!(
                        "Found: HKLM\\{} ({})",
                        device.key_path, device.description
                    ));
                    for (name, value) in [
                        "ConservationIdleTime",
                        "IdlePowerState",
                        "PerformanceIdleTime",
                    ]
                    .iter()
                    .zip(&device.current)
                    {
                        self.append_log(&format!(
                            "  {name} = {}",
                            registry::display_value(value.as_deref())
                        ));
                    }
                }
                self.devices.set_collection(
                    report
                        .devices
                        .iter()
                        .map(|d| {
                            format!(
                                "{} | {} | HKLM\\{}",
                                d.description,
                                registry::status(d),
                                d.key_path
                            )
                        })
                        .collect(),
                );
                if report.devices.is_empty() {
                    self.status
                        .set_text("No eligible Realtek PowerSettings entries found.");
                    self.append_log("Scan complete: no eligible entries found; nothing changed.");
                } else {
                    self.status
                        .set_text("Review detected entries before applying the fix.");
                    self.append_log(&format!(
                        "Scan complete: {} eligible entry/entries and {} warning(s).",
                        report.devices.len(),
                        report.warnings.len()
                    ));
                }
                *self.found.borrow_mut() = report.devices;
            }
            Err(error) => self.show_error("Scan failed", &error),
        }
    }

    fn do_fix(&self) {
        let (entry_count, needs_fix) = {
            let found = self.found.borrow();
            (
                found.len(),
                found
                    .iter()
                    .any(|device| registry::status(device) != "Fixed"),
            )
        };
        if entry_count == 0 {
            self.append_log("Fix skipped: no eligible Realtek entries were detected.");
            self.status
                .set_text("No eligible Realtek entries were found. Nothing was changed.");
            nwg::simple_message(
                "Nothing to fix",
                "No eligible Realtek audio entries were found. Nothing was changed.",
            );
            return;
        }
        if !needs_fix {
            self.append_log(
                "Fix skipped: all detected Realtek entries already contain the fix values.",
            );
            self.status
                .set_text("All detected Realtek entries already have the fix applied.");
            nwg::simple_message(
                "Fix already applied",
                "All detected Realtek audio entries already have the fix applied. Nothing was changed and no additional backup was created.",
            );
            return;
        }
        if !self.confirm("Confirm registry change", "A new backup will be saved, then only the listed Realtek power values will be changed. Continue?") { return; }
        self.append_log("Fix confirmed. Requesting UAC for the minimal registry helper...");
        let result = run_elevated_helper("apply", None, None);
        match result {
            Ok(report) if report.success => {
                self.append_lines(&report.lines);
                self.append_log("Fix completed successfully. Reboot required.");
                self.status.set_text(&report.summary);
                nwg::simple_message("Fix applied", &report.summary);
            }
            Ok(report) => {
                self.append_lines(&report.lines);
                self.show_error("Could not apply fix", &report.summary);
            }
            Err(error) => self.show_error("Could not apply fix", &error),
        }
    }

    fn choose_restore(&self) {
        self.append_log("Opening backup file picker...");
        if !self.file_dialog.run(Some(&self.window)) {
            self.append_log("File selection cancelled.");
            return;
        }
        match self.file_dialog.get_selected_item() {
            Ok(path) => self.confirm_restore(Some(PathBuf::from(path))),
            Err(error) => self.show_error("Could not read selection", &error),
        }
    }

    fn confirm_restore(&self, selected: Option<PathBuf>) {
        let path = match selected {
            Some(path) => path,
            None => match registry::latest_backup() {
                Ok(Some(path)) => path,
                Ok(None) => {
                    self.show_error("Nothing to restore", &"No backup exists yet");
                    return;
                }
                Err(error) => {
                    self.show_error("Could not locate backups", &error);
                    return;
                }
            },
        };
        let label = path.display().to_string();
        self.append_log(&format!(
            "Validating restore file before requesting elevation: {label}"
        ));
        let inspection = match registry::inspect_backup(&path) {
            Ok(inspection) => inspection,
            Err(error) => {
                self.show_error("Restore file rejected", &error);
                return;
            }
        };
        self.append_log(&format!(
            "Restore validation passed: {} entry/entries, schema {}.",
            inspection.entries,
            if inspection.legacy {
                "legacy v1"
            } else {
                "v2 with SHA-256"
            }
        ));
        self.append_log(&format!(
            "Restore content fingerprint: {}",
            inspection.file_sha256
        ));
        if !self.confirm("Confirm restore", &format!("Restore {label}?\n\nValidated entries: {}\nSchema: {}\n\nA fresh safety backup will be created first. Windows will request administrator approval.", inspection.entries, if inspection.legacy { "legacy v1 (pre-checksum)" } else { "v2, checksum verified" })) { return; }
        self.append_log(&format!(
            "Restore confirmed from {label}. Requesting UAC for the minimal registry helper..."
        ));
        let result = run_elevated_helper("restore", Some(&path), Some(&inspection.file_sha256));
        match result {
            Ok(report) if report.success => {
                self.append_lines(&report.lines);
                self.append_log("Restore completed successfully. Reboot required.");
                self.status.set_text(&report.summary);
                nwg::simple_message("Backup restored", &report.summary);
            }
            Ok(report) => {
                self.append_lines(&report.lines);
                self.show_error("Restore rejected or failed", &report.summary);
            }
            Err(error) => self.show_error("Restore rejected or failed", &error),
        }
    }

    fn confirm(&self, title: &str, content: &str) -> bool {
        nwg::modal_message(
            &self.window,
            &nwg::MessageParams {
                title,
                content,
                buttons: nwg::MessageButtons::YesNo,
                icons: nwg::MessageIcons::Warning,
            },
        ) == nwg::MessageChoice::Yes
    }

    fn toggle_advanced(&self) {
        let open = !self.advanced_open.get();
        self.advanced_open.set(open);
        self.log_label.set_visible(open);
        self.log.set_visible(open);
        self.advanced
            .set_text(if open { "Advanced ^" } else { "Advanced v" });
        self.window.set_size(650, if open { 655 } else { 405 });
    }

    fn show_error(&self, title: &str, error: &dyn std::fmt::Display) {
        self.append_log(&format!("ERROR - {title}: {error}"));
        self.status.set_text(&format!("{title}: {error}"));
        nwg::error_message(title, &format!("{error}"));
    }
}

fn main() {
    let arguments: Vec<String> = env::args().collect();
    if arguments
        .iter()
        .any(|argument| argument == "--elevated-helper")
    {
        std::process::exit(run_helper_mode(&arguments));
    }
    if let Err(error) = nwg::init() {
        nwg::error_message(
            "Audio Fade Fixer could not start",
            &format!("Windows GUI initialization failed: {error}"),
        );
        return;
    }
    let mut font = nwg::Font::default();
    if let Err(error) = nwg::Font::builder()
        .family("Segoe UI")
        .size(14)
        .build(&mut font)
    {
        nwg::error_message(
            "Audio Fade Fixer could not start",
            &format!("Font initialization failed: {error}"),
        );
        return;
    }
    nwg::Font::set_global_default(Some(font));
    let _app = match App::build() {
        Ok(app) => app,
        Err(error) => {
            nwg::error_message(
                "Audio Fade Fixer could not start",
                &format!("User interface initialization failed: {error}"),
            );
            return;
        }
    };
    nwg::dispatch_thread_events();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_windows_arguments_without_shell_interpretation() {
        assert_eq!(
            quote_windows_arg(std::ffi::OsStr::new("simple")),
            r#""simple""#
        );
        assert_eq!(
            quote_windows_arg(std::ffi::OsStr::new(r"C:\Backup Folder\file.json")),
            r#""C:\Backup Folder\file.json""#
        );
        assert_eq!(
            quote_windows_arg(std::ffi::OsStr::new(r"C:\Trailing\")),
            r#""C:\Trailing\\""#
        );
    }

    #[test]
    fn operation_nonce_is_fixed_hex() {
        let nonce = operation_nonce();
        assert_eq!(nonce.len(), 32);
        assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
