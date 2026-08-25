use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    env,
    ffi::OsString,
    fs,
    fs::OpenOptions,
    io::{self, Read, Write},
    os::windows::{
        ffi::OsStringExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf, Prefix},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use winapi::{
    shared::{minwindef::MAX_PATH, winerror::S_OK},
    um::{
        shlobj::{CSIDL_COMMON_APPDATA, SHGFP_TYPE_CURRENT, SHGetFolderPathW},
        sysinfoapi::GetSystemDirectoryW,
    },
};
use winreg::{
    RegKey, RegValue,
    enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_BINARY},
};

const CLASS_PATH: &str =
    r"SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}";
const VALUES: [&str; 3] = [
    "ConservationIdleTime",
    "IdlePowerState",
    "PerformanceIdleTime",
];
const FIXED: [[u8; 4]; 3] = [[0xff; 4], [0; 4], [0xff; 4]];
const BACKUP_VERSION: u32 = 2;
const MAX_BACKUP_BYTES: u64 = 256 * 1024;
const MAX_ENTRIES: usize = 64;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

#[derive(Clone, Debug)]
pub struct Device {
    pub key_path: String,
    pub description: String,
    pub current: [Option<Vec<u8>>; 3],
}

#[derive(Debug)]
pub struct ScanReport {
    pub devices: Vec<Device>,
    pub warnings: Vec<String>,
    pub examined: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationReport {
    pub success: bool,
    pub summary: String,
    pub file: Option<PathBuf>,
    pub lines: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupPayload {
    version: u32,
    created_unix_seconds: u64,
    entries: Vec<BackupEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupFile {
    version: u32,
    created_unix_seconds: u64,
    entries: Vec<BackupEntry>,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyBackup {
    created_utc: String,
    entries: Vec<BackupEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupEntry {
    key_path: String,
    description: String,
    values: [Option<Vec<u8>>; 3],
}

struct ValidatedBackup {
    entries: Vec<BackupEntry>,
    legacy: bool,
}

pub struct BackupInspection {
    pub entries: usize,
    pub legacy: bool,
    pub file_sha256: String,
}

pub fn scan() -> io::Result<ScanReport> {
    let root = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(CLASS_PATH, KEY_READ)?;
    let mut devices = Vec::new();
    let mut warnings = Vec::new();
    let mut examined = 0;
    for result in root.enum_keys() {
        let name = match result {
            Ok(name) => name,
            Err(error) => {
                warnings.push(format!("Could not enumerate an audio driver key: {error}"));
                continue;
            }
        };
        if !valid_driver_key_name(&name) {
            continue;
        }
        examined += 1;
        let driver = match root.open_subkey_with_flags(&name, KEY_READ) {
            Ok(driver) => driver,
            Err(error) => {
                warnings.push(format!(
                    "Could not inspect audio driver key {name}: {error}"
                ));
                continue;
            }
        };
        let description: String = match driver.get_value("DriverDesc") {
            Ok(description) => description,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                warnings.push(format!(
                    "Could not read DriverDesc from key {name}: {error}"
                ));
                continue;
            }
        };
        if !is_realtek(&description) {
            continue;
        }
        let power = match driver.open_subkey_with_flags("PowerSettings", KEY_READ) {
            Ok(power) => power,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                warnings.push(format!(
                    "Could not read Realtek key {name}\\PowerSettings: {error}"
                ));
                continue;
            }
        };
        let mut current: [Option<Vec<u8>>; 3] = Default::default();
        let mut valid = true;
        for (index, value) in VALUES.iter().enumerate() {
            match read_binary_or_missing(&power, value) {
                Ok(bytes) => current[index] = bytes,
                Err(error) => {
                    warnings.push(format!("Rejected Realtek key {name}: {error}"));
                    valid = false;
                    break;
                }
            }
        }
        if valid {
            devices.push(Device {
                key_path: format!(r"{}\{}\PowerSettings", CLASS_PATH, name),
                description,
                current,
            });
        }
    }
    Ok(ScanReport {
        devices,
        warnings,
        examined,
    })
}

fn read_binary_or_missing(key: &RegKey, name: &str) -> io::Result<Option<Vec<u8>>> {
    match key.get_raw_value(name) {
        Ok(value) if value.vtype == REG_BINARY => Ok(Some(value.bytes)),
        Ok(_) => Err(invalid(format!("registry value {name} is not REG_BINARY"))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Elevated entry point. Rescans and snapshots immediately before writing.
pub fn apply_all() -> io::Result<OperationReport> {
    let report = scan()?;
    if !report.warnings.is_empty() {
        return Err(invalid(format!(
            "Scan produced {} warning(s); refusing to write until every target can be inspected",
            report.warnings.len()
        )));
    }
    let pending: Vec<_> = report
        .devices
        .into_iter()
        .filter(|device| status(device) != "Fixed")
        .collect();
    if pending.is_empty() {
        return Ok(OperationReport {
            success: true,
            summary: "All detected Realtek entries already have the fix applied.".into(),
            file: None,
            lines: vec!["No registry values were changed and no backup was created.".into()],
        });
    }
    // The scan above is the fresh snapshot used by the backup and rollback journal.
    for device in &pending {
        validate_live_target(&device.key_path)?;
    }
    let backup_path = save_backup(&pending)?;
    let mut lines = vec![format!("Backup file: {}", backup_path.display())];
    let writes = pending
        .iter()
        .flat_map(|device| {
            (0..3).map(move |index| PlannedWrite {
                key_path: device.key_path.clone(),
                value_index: index,
                before: device.current[index].clone(),
                after: Some(FIXED[index].to_vec()),
            })
        })
        .collect::<Vec<_>>();
    if let Err(error) = execute_with_rollback(&writes, &mut lines) {
        return Ok(OperationReport {
            success: false,
            summary: error.to_string(),
            file: Some(backup_path),
            lines,
        });
    }
    Ok(OperationReport {
        success: true,
        summary: "Fix applied successfully. Reboot Windows for it to take effect.".into(),
        file: Some(backup_path),
        lines,
    })
}

#[derive(Clone)]
struct PlannedWrite {
    key_path: String,
    value_index: usize,
    before: Option<Vec<u8>>,
    after: Option<Vec<u8>>,
}

fn execute_with_rollback(writes: &[PlannedWrite], lines: &mut Vec<String>) -> io::Result<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    for (completed, write) in writes.iter().enumerate() {
        if let Err(error) = validate_live_target(&write.key_path) {
            return rollback_or_error(writes, completed, error, lines);
        }
        let key = match hklm.open_subkey_with_flags(&write.key_path, KEY_READ | KEY_WRITE) {
            Ok(key) => key,
            Err(error) => return rollback_or_error(writes, completed, error, lines),
        };
        let current = match read_binary_or_missing(&key, VALUES[write.value_index]) {
            Ok(current) => current,
            Err(error) => return rollback_or_error(writes, completed, error, lines),
        };
        if current != write.before {
            let error = invalid(format!(
                "{} changed after validation; refusing a stale write",
                VALUES[write.value_index]
            ));
            return rollback_or_error(writes, completed, error, lines);
        }
        lines.push(format!(
            "HKLM\\{}\\{}: {} -> {}",
            write.key_path,
            VALUES[write.value_index],
            display_value(current.as_deref()),
            display_value(write.after.as_deref())
        ));
        if let Err(error) = write_optional(&key, VALUES[write.value_index], write.after.as_deref())
        {
            return rollback_or_error(writes, completed, error, lines);
        }
        match read_binary_or_missing(&key, VALUES[write.value_index]) {
            Ok(value) if value == write.after => (),
            Ok(_) => {
                return rollback_or_error(
                    writes,
                    completed + 1,
                    invalid("Registry write verification returned a different value"),
                    lines,
                );
            }
            Err(error) => return rollback_or_error(writes, completed + 1, error, lines),
        }
    }
    Ok(())
}

fn rollback_or_error(
    writes: &[PlannedWrite],
    completed: usize,
    original: io::Error,
    lines: &mut Vec<String>,
) -> io::Result<()> {
    lines.push(format!(
        "Write failed: {original}. Starting automatic rollback."
    ));
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut rollback_errors = Vec::new();
    for write in writes[..completed].iter().rev() {
        match hklm
            .open_subkey_with_flags(&write.key_path, KEY_READ | KEY_WRITE)
            .and_then(|key| {
                write_optional(&key, VALUES[write.value_index], write.before.as_deref())
            }) {
            Ok(()) => lines.push(format!(
                "Rolled back HKLM\\{}\\{}",
                write.key_path, VALUES[write.value_index]
            )),
            Err(error) => rollback_errors.push(format!(
                "HKLM\\{}\\{}: {error}",
                write.key_path, VALUES[write.value_index]
            )),
        }
    }
    if rollback_errors.is_empty() {
        Err(io::Error::new(
            original.kind(),
            format!("{original}; automatic rollback succeeded"),
        ))
    } else {
        Err(io::Error::new(
            original.kind(),
            format!(
                "{original}; ROLLBACK INCOMPLETE: {}",
                rollback_errors.join("; ")
            ),
        ))
    }
}

fn write_optional(key: &RegKey, name: &str, value: Option<&[u8]>) -> io::Result<()> {
    match value {
        Some(bytes) => key.set_raw_value(
            name,
            &RegValue {
                vtype: REG_BINARY,
                bytes: bytes.to_vec(),
            },
        ),
        None => match key.delete_value(name) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        },
    }
}

fn validate_live_target(key_path: &str) -> io::Result<()> {
    validate_key_path(key_path)?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let driver_path = key_path
        .strip_suffix(r"\PowerSettings")
        .ok_or_else(|| invalid("Invalid PowerSettings suffix"))?;
    let driver = hklm.open_subkey_with_flags(driver_path, KEY_READ)?;
    let description: String = driver.get_value("DriverDesc")?;
    if !is_realtek(&description) {
        return Err(invalid(
            "Registry target is no longer a Realtek audio driver",
        ));
    }
    let power = hklm.open_subkey_with_flags(key_path, KEY_READ)?;
    for value in VALUES {
        read_binary_or_missing(&power, value)?;
    }
    Ok(())
}

fn known_program_data() -> io::Result<PathBuf> {
    let mut buffer = [0_u16; MAX_PATH];
    // SAFETY: `buffer` is writable for MAX_PATH UTF-16 elements, all optional
    // handles are null as permitted by SHGetFolderPathW, and the pointer lives
    // until the call returns.
    let result = unsafe {
        SHGetFolderPathW(
            std::ptr::null_mut(),
            CSIDL_COMMON_APPDATA,
            std::ptr::null_mut(),
            SHGFP_TYPE_CURRENT,
            buffer.as_mut_ptr(),
        )
    };
    if result != S_OK {
        return Err(io::Error::other(format!(
            "SHGetFolderPathW failed: 0x{result:08X}"
        )));
    }
    let length = buffer
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(buffer.len());
    Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
}

fn known_system_directory() -> io::Result<PathBuf> {
    let mut buffer = [0_u16; MAX_PATH];
    // SAFETY: `buffer` is a valid writable UTF-16 array and its exact capacity
    // is passed to the synchronous Windows API.
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
}

fn storage_root_path() -> io::Result<PathBuf> {
    Ok(known_program_data()?.join("AudioFadeFixer"))
}

fn protected_root() -> io::Result<PathBuf> {
    let root = storage_root_path()?;
    if root.exists() {
        reject_reparse_directory(&root)?;
    } else {
        fs::create_dir(&root)?;
    }
    for path in [root.join("backups"), root.join("operations")] {
        if path.exists() {
            reject_reparse_directory(&path)?;
        } else {
            fs::create_dir(&path)?;
        }
    }
    Ok(root)
}

fn reject_reparse_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(invalid(format!(
            "Protected storage path is not a regular directory: {}",
            path.display()
        )));
    }
    Ok(())
}

/// Called only by the elevated helper. Removes user write access while retaining
/// read access so the unelevated GUI can display backups and operation reports.
pub fn harden_storage_permissions() -> io::Result<()> {
    let root = protected_root()?;
    let canonical_root = fs::canonicalize(&root)?;
    let canonical_program_data = fs::canonicalize(known_program_data()?)?;
    if !canonical_root.starts_with(&canonical_program_data) {
        return Err(invalid("Protected storage resolved outside PROGRAMDATA"));
    }
    let icacls = known_system_directory()?.join("icacls.exe");
    let owner_status = Command::new(&icacls)
        .arg(&canonical_root)
        .args(["/setowner", "*S-1-5-32-544"])
        .status()?;
    if !owner_status.success() {
        return Err(io::Error::other(format!(
            "icacls owner update failed with status {owner_status}"
        )));
    }
    let status = Command::new(&icacls)
        .arg(&canonical_root)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "*S-1-5-32-545:(OI)(CI)RX",
        ])
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "icacls failed with status {status}"
        )));
    }
    Ok(())
}

fn save_backup(devices: &[Device]) -> io::Result<PathBuf> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    let payload = BackupPayload {
        version: BACKUP_VERSION,
        created_unix_seconds: now.as_secs(),
        entries: devices
            .iter()
            .map(|device| BackupEntry {
                key_path: device.key_path.clone(),
                description: device.description.clone(),
                values: device.current.clone(),
            })
            .collect(),
    };
    let backup = BackupFile {
        version: payload.version,
        created_unix_seconds: payload.created_unix_seconds,
        entries: payload.entries.clone(),
        sha256: payload_checksum(&payload)?,
    };
    let path = protected_root()?.join("backups").join(format!(
        "backup-{}-{:09}.json",
        now.as_secs(),
        now.subsec_nanos()
    ));
    create_new_synced(
        &path,
        &serde_json::to_vec_pretty(&backup).map_err(io::Error::other)?,
    )?;
    Ok(path)
}

fn create_new_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn payload_checksum(payload: &BackupPayload) -> io::Result<String> {
    let bytes = serde_json::to_vec(payload).map_err(io::Error::other)?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn latest_backup() -> io::Result<Option<PathBuf>> {
    let mut candidates = Vec::new();
    candidates.push(storage_root_path()?.join("backups"));
    if let Some(local) = env::var_os("LOCALAPPDATA") {
        candidates.push(PathBuf::from(local).join("AudioFadeFixer").join("backups"));
    }
    latest_path_by_modified_time(&candidates)
}

fn latest_path_by_modified_time(directories: &[PathBuf]) -> io::Result<Option<PathBuf>> {
    let mut newest: Option<(SystemTime, PathBuf)> = None;
    for directory in directories {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if !path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            {
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            let Ok(modified) = metadata.modified() else {
                continue;
            };
            if newest.as_ref().is_none_or(|(time, _)| modified > *time) {
                newest = Some((modified, path));
            }
        }
    }
    Ok(newest.map(|(_, path)| path))
}

pub fn restore_latest() -> io::Result<OperationReport> {
    let path = latest_backup()?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No backup exists yet"))?;
    restore_file(&path)
}

pub fn restore_file(path: &Path) -> io::Result<OperationReport> {
    let bytes = read_regular_file_limited(path)?;
    restore_validated_bytes(path, &bytes)
}

pub fn restore_file_with_fingerprint(
    path: &Path,
    expected_sha256: &str,
) -> io::Result<OperationReport> {
    if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid(
            "Expected restore fingerprint is not a SHA-256 value",
        ));
    }
    let bytes = read_regular_file_limited(path)?;
    let actual = sha256_hex(&bytes);
    if !constant_time_ascii_eq(actual.as_bytes(), expected_sha256.as_bytes()) {
        return Err(invalid(
            "Restore file changed after user confirmation; refusing to continue",
        ));
    }
    restore_validated_bytes(path, &bytes)
}

fn restore_validated_bytes(path: &Path, bytes: &[u8]) -> io::Result<OperationReport> {
    let backup = parse_and_validate_backup(bytes)?;
    let mut live_devices = Vec::with_capacity(backup.entries.len());
    for entry in &backup.entries {
        live_devices.push(read_live_device(&entry.key_path)?);
    }
    let safety_backup = save_backup(&live_devices)?;
    let mut lines = vec![
        format!("Validated restore file: {}", path.display()),
        format!("Pre-restore safety backup: {}", safety_backup.display()),
    ];
    if backup.legacy {
        lines.push(
            "Legacy v1 backup accepted with strict structural validation; it predates checksums."
                .into(),
        );
    } else {
        lines.push("Backup schema v2 and SHA-256 checksum validated.".into());
    }
    let writes = backup
        .entries
        .iter()
        .zip(&live_devices)
        .flat_map(|(entry, live)| {
            (0..3).map(move |index| PlannedWrite {
                key_path: entry.key_path.clone(),
                value_index: index,
                before: live.current[index].clone(),
                after: entry.values[index].clone(),
            })
        })
        .collect::<Vec<_>>();
    if let Err(error) = execute_with_rollback(&writes, &mut lines) {
        return Ok(OperationReport {
            success: false,
            summary: error.to_string(),
            file: Some(safety_backup),
            lines,
        });
    }
    Ok(OperationReport {
        success: true,
        summary: "Backup restored successfully. Reboot Windows to finish.".into(),
        file: Some(path.to_path_buf()),
        lines,
    })
}

pub fn inspect_backup(path: &Path) -> io::Result<BackupInspection> {
    let bytes = read_regular_file_limited(path)?;
    let backup = parse_and_validate_backup(&bytes)?;
    // Validate that every referenced target currently exists and is still Realtek,
    // but do not request write access or modify anything.
    for entry in &backup.entries {
        read_live_device(&entry.key_path)?;
    }
    Ok(BackupInspection {
        entries: backup.entries.len(),
        legacy: backup.legacy,
        file_sha256: sha256_hex(&bytes),
    })
}

fn read_regular_file_limited(path: &Path) -> io::Result<Vec<u8>> {
    validate_local_absolute_path(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(invalid(
            "Backup must be a regular file, not a link, reparse point, or directory",
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_BACKUP_BYTES {
        return Err(invalid(format!(
            "Backup size must be 1 to {MAX_BACKUP_BYTES} bytes"
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_BACKUP_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BACKUP_BYTES {
        return Err(invalid(
            "Backup grew beyond the size limit while being read",
        ));
    }
    Ok(bytes)
}

fn validate_local_absolute_path(path: &Path) -> io::Result<()> {
    match path.components().next() {
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) => {}
        _ => {
            return Err(invalid(
                "Backup path must be an absolute local drive path; network and device paths are rejected",
            ));
        }
    }
    if !path.is_absolute() {
        return Err(invalid("Backup path must be absolute"));
    }
    Ok(())
}

fn parse_and_validate_backup(bytes: &[u8]) -> io::Result<ValidatedBackup> {
    if let Ok(file) = serde_json::from_slice::<BackupFile>(bytes) {
        if file.version != BACKUP_VERSION {
            return Err(invalid(format!(
                "Unsupported backup schema version {}",
                file.version
            )));
        }
        let payload = BackupPayload {
            version: file.version,
            created_unix_seconds: file.created_unix_seconds,
            entries: file.entries,
        };
        validate_entries(&payload.entries)?;
        let expected = payload_checksum(&payload)?;
        if !constant_time_ascii_eq(expected.as_bytes(), file.sha256.as_bytes()) {
            return Err(invalid(
                "Backup SHA-256 checksum does not match; the file may be damaged or altered",
            ));
        }
        return Ok(ValidatedBackup {
            entries: payload.entries,
            legacy: false,
        });
    }
    let legacy: LegacyBackup = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("Backup JSON or schema is invalid: {error}")))?;
    validate_legacy_timestamp(&legacy.created_utc)?;
    validate_entries(&legacy.entries)?;
    Ok(ValidatedBackup {
        entries: legacy.entries,
        legacy: true,
    })
}

fn constant_time_ascii_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn validate_entries(entries: &[BackupEntry]) -> io::Result<()> {
    if entries.is_empty() || entries.len() > MAX_ENTRIES {
        return Err(invalid(format!(
            "Backup must contain 1 to {MAX_ENTRIES} entries"
        )));
    }
    let mut unique = HashSet::new();
    for entry in entries {
        validate_key_path(&entry.key_path)?;
        if !unique.insert(entry.key_path.to_ascii_lowercase()) {
            return Err(invalid("Backup contains a duplicate registry target"));
        }
        if entry.description.is_empty()
            || entry.description.len() > 256
            || entry.description.chars().any(char::is_control)
        {
            return Err(invalid("Backup contains an invalid device description"));
        }
        if !is_realtek(&entry.description) {
            return Err(invalid(
                "Backup device description does not identify Realtek",
            ));
        }
        if entry
            .values
            .iter()
            .any(|value| value.as_ref().is_some_and(|bytes| bytes.len() != 4))
        {
            return Err(invalid(
                "Every stored binary value must be exactly four bytes",
            ));
        }
    }
    Ok(())
}

fn validate_legacy_timestamp(value: &str) -> io::Result<()> {
    if let Some(timestamp) = value.strip_prefix("unix-seconds:") {
        let Some((seconds, nanoseconds)) = timestamp.split_once('.') else {
            return Err(invalid("Invalid legacy backup timestamp"));
        };
        if !seconds.is_empty()
            && seconds.bytes().all(|byte| byte.is_ascii_digit())
            && seconds.parse::<u64>().is_ok()
            && nanoseconds.len() == 9
            && nanoseconds.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Ok(());
        }
        return Err(invalid("Invalid legacy backup timestamp"));
    }

    if (20..=40).contains(&value.len())
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value.as_bytes().get(10) == Some(&b'T')
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || matches!(byte, b'-' | b':' | b'.' | b'+' | b'T' | b'Z')
        })
    {
        Ok(())
    } else {
        Err(invalid("Invalid legacy backup timestamp"))
    }
}

fn read_live_device(key_path: &str) -> io::Result<Device> {
    validate_live_target(key_path)?;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let driver_path = key_path
        .strip_suffix(r"\PowerSettings")
        .ok_or_else(|| invalid("Invalid suffix"))?;
    let driver = hklm.open_subkey_with_flags(driver_path, KEY_READ)?;
    let description: String = driver.get_value("DriverDesc")?;
    let power = hklm.open_subkey_with_flags(key_path, KEY_READ)?;
    let mut current: [Option<Vec<u8>>; 3] = Default::default();
    for (index, value) in VALUES.iter().enumerate() {
        current[index] = read_binary_or_missing(&power, value)?;
    }
    Ok(Device {
        key_path: key_path.to_owned(),
        description,
        current,
    })
}

fn validate_key_path(path: &str) -> io::Result<()> {
    let prefix = format!(r"{}\", CLASS_PATH);
    let driver = path
        .strip_prefix(&prefix)
        .and_then(|rest| rest.strip_suffix(r"\PowerSettings"))
        .ok_or_else(|| invalid("Registry path is outside the permitted Realtek audio scope"))?;
    if !valid_driver_key_name(driver) {
        return Err(invalid(
            "Registry path lacks an exact four-digit driver key",
        ));
    }
    Ok(())
}

fn valid_driver_key_name(name: &str) -> bool {
    name.len() == 4 && name.bytes().all(|byte| byte.is_ascii_digit())
}
fn is_realtek(description: &str) -> bool {
    description
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("realtek")
}
fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
pub fn display_value(value: Option<&[u8]>) -> String {
    value.map_or_else(
        || "<missing>".into(),
        |bytes| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
        },
    )
}
pub fn status(device: &Device) -> &'static str {
    if (0..3).all(|index| device.current[index].as_deref() == Some(&FIXED[index])) {
        "Fixed"
    } else {
        "Needs fix"
    }
}

pub fn operation_report_path(nonce: &str) -> io::Result<PathBuf> {
    validate_nonce(nonce)?;
    Ok(storage_root_path()?
        .join("operations")
        .join(format!("operation-{}.json", nonce.to_ascii_lowercase())))
}

fn validate_nonce(nonce: &str) -> io::Result<()> {
    if nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(invalid(
            "Operation nonce must be exactly 32 hexadecimal characters",
        ))
    }
}

pub fn write_operation_report(nonce: &str, report: &OperationReport) -> io::Result<PathBuf> {
    let path = operation_report_path(nonce)?;
    create_new_synced(
        &path,
        &serde_json::to_vec_pretty(report).map_err(io::Error::other)?,
    )?;
    Ok(path)
}

pub fn read_operation_report(nonce: &str) -> io::Result<OperationReport> {
    let path = operation_report_path(nonce)?;
    let bytes = read_regular_file_limited(&path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("Invalid helper report: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, thread, time::Duration};

    fn entry() -> BackupEntry {
        BackupEntry {
            key_path: format!(r"{}\0003\PowerSettings", CLASS_PATH),
            description: "Realtek High Definition Audio".into(),
            values: [Some(vec![1, 2, 3, 4]), None, Some(vec![0; 4])],
        }
    }

    #[test]
    fn recognizes_fixed_values() {
        let device = Device {
            key_path: String::new(),
            description: String::new(),
            current: [Some(vec![255; 4]), Some(vec![0; 4]), Some(vec![255; 4])],
        };
        assert_eq!(status(&device), "Fixed");
    }

    #[test]
    fn exact_paths_only() {
        assert!(validate_key_path(&format!(r"{}\0003\PowerSettings", CLASS_PATH)).is_ok());
        for path in [
            r"SOFTWARE\Bad\PowerSettings".into(),
            format!(r"{}\..\PowerSettings", CLASS_PATH),
            format!(r"{}\0003\PowerSettings\Extra", CLASS_PATH),
            format!(r"{}\00033\PowerSettings", CLASS_PATH),
        ] {
            assert!(validate_key_path(&path).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn rejects_unknown_json_fields() {
        assert!(
            serde_json::from_str::<BackupFile>(
                r#"{"version":2,"created_unix_seconds":1,"entries":[],"sha256":"x","extra":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn detects_checksum_tampering() {
        let payload = BackupPayload {
            version: 2,
            created_unix_seconds: 1,
            entries: vec![entry()],
        };
        let file = BackupFile {
            version: 2,
            created_unix_seconds: 1,
            entries: payload.entries.clone(),
            sha256: payload_checksum(&payload).unwrap(),
        };
        let mut bytes = serde_json::to_vec(&file).unwrap();
        let position = bytes.iter().position(|byte| *byte == b'1').unwrap();
        bytes[position] = b'2';
        assert!(parse_and_validate_backup(&bytes).is_err());
    }

    #[test]
    fn rejects_duplicates_wrong_lengths_and_non_realtek() {
        let first = entry();
        assert!(validate_entries(&[first.clone(), first.clone()]).is_err());
        let mut wrong = first.clone();
        wrong.values[0] = Some(vec![1]);
        assert!(validate_entries(&[wrong]).is_err());

        let too_many = (0..=MAX_ENTRIES)
            .map(|index| {
                let mut item = entry();
                item.key_path = format!(r"{}\{:04}\PowerSettings", CLASS_PATH, index);
                item
            })
            .collect::<Vec<_>>();
        assert!(validate_entries(&too_many).is_err());
        let mut wrong = first;
        wrong.description = "Unrelated Audio".into();
        assert!(validate_entries(&[wrong]).is_err());
    }

    #[test]
    fn validates_nonce() {
        assert!(validate_nonce("../../malicious").is_err());
        assert!(validate_nonce("0123456789abcdef0123456789ABCDEF").is_ok());
    }

    #[test]
    fn constant_time_compare_checks_content_and_length() {
        assert!(constant_time_ascii_eq(b"abc", b"abc"));
        assert!(!constant_time_ascii_eq(b"abc", b"abd"));
        assert!(!constant_time_ascii_eq(b"abc", b"ab"));
    }

    #[test]
    fn latest_backup_uses_modified_time_not_mixed_filename_formats() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = env::temp_dir().join(format!("audio-fade-fixer-test-{unique}"));
        fs::create_dir(&directory).unwrap();
        let misleading_old = directory.join("backup-99999999-legacy.json");
        let newer = directory.join("backup-100-modern.json");
        fs::write(&misleading_old, b"old").unwrap();
        thread::sleep(Duration::from_millis(20));
        fs::write(&newer, b"new").unwrap();
        assert_eq!(
            latest_path_by_modified_time(std::slice::from_ref(&directory)).unwrap(),
            Some(newer)
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_oversized_files_before_json_parsing() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!("audio-fade-fixer-oversized-{unique}.json"));
        let file = File::create(&path).unwrap();
        file.set_len(MAX_BACKUP_BYTES + 1).unwrap();
        assert!(read_regular_file_limited(&path).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn fingerprint_binds_restore_to_confirmed_content() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!("audio-fade-fixer-swap-{unique}.json"));
        fs::write(&path, b"replacement content").unwrap();
        let error = restore_file_with_fingerprint(&path, &"0".repeat(64)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed after user confirmation")
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn accepts_strict_legacy_backup_and_rejects_bad_version() {
        let legacy = LegacyBackup {
            created_utc: "2026-08-25T12:00:00Z".into(),
            entries: vec![entry()],
        };
        let legacy_bytes = serde_json::to_vec(&legacy).unwrap();
        assert!(parse_and_validate_backup(&legacy_bytes).unwrap().legacy);

        let payload = BackupPayload {
            version: 99,
            created_unix_seconds: 1,
            entries: vec![entry()],
        };
        let file = BackupFile {
            version: payload.version,
            created_unix_seconds: payload.created_unix_seconds,
            entries: payload.entries.clone(),
            sha256: payload_checksum(&payload).unwrap(),
        };
        assert!(parse_and_validate_backup(&serde_json::to_vec(&file).unwrap()).is_err());
    }

    #[test]
    fn accepts_intermediate_legacy_timestamp_without_relaxing_validation() {
        let mut legacy = LegacyBackup {
            created_utc: "unix-seconds:1787674460.218951600".into(),
            entries: vec![entry()],
        };
        assert!(
            parse_and_validate_backup(&serde_json::to_vec(&legacy).unwrap())
                .unwrap()
                .legacy
        );

        for invalid_timestamp in [
            "unix-seconds:",
            "unix-seconds:1787674460",
            "unix-seconds:1787674460.21895160",
            "unix-seconds:1787674460.2189516000",
            "unix-seconds:1787674460.21895x600",
            "unix-seconds:../../.218951600",
        ] {
            legacy.created_utc = invalid_timestamp.into();
            assert!(parse_and_validate_backup(&serde_json::to_vec(&legacy).unwrap()).is_err());
        }
    }

    #[test]
    fn realtek_identity_must_start_the_description() {
        assert!(is_realtek("Realtek High Definition Audio"));
        assert!(is_realtek("  Realtek(R) Audio"));
        assert!(!is_realtek("NotRealtek Audio"));
        assert!(!is_realtek("Unrelated Audio (Realtek compatible)"));
    }
}
