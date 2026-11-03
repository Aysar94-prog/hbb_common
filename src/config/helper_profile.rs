use std::{collections::HashMap, path::PathBuf};

pub(super) fn profile_path(root: PathBuf, id: &str) -> Option<PathBuf> {
    uuid::Uuid::parse_str(id).ok().map(|id| root.join("helper-profiles").join(id.to_string()))
}

#[cfg(windows)]
fn read_install_value(name: &str) -> Option<String> {
    use winapi::um::winreg::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY};
        let key: Vec<u16> = "Software\\SubnetDesk\\Helper\0".encode_utf16().collect();
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let mut buffer = [0u16; 2048];
        let mut bytes = (buffer.len() * 2) as u32;
        let status = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), name.as_ptr(),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(), &mut bytes) };
        if status != 0 { return None; }
        let length = buffer.iter().position(|v| *v == 0)?;
        String::from_utf16(&buffer[..length]).ok()
}

#[cfg(windows)]
pub(super) fn installed_profile() -> Option<String> {
    let install = read_install_value("InstallFolder")?;
    let executable = std::env::current_exe().ok()?;
    if !executable.parent()?.to_string_lossy().trim_end_matches('\\')
        .eq_ignore_ascii_case(install.trim_end_matches('\\')) { return None; }
    read_install_value("ProfileId")
}

#[cfg(windows)]
pub(super) fn install_epoch() -> Option<String> {
    installed_profile()?;
    read_install_value("ReceiverInstallId")
}

pub(super) fn apply_install_lock(options: &mut HashMap<String, String>, epoch: &str) {
    if !epoch.is_empty() && options.get("receiver-install-id").map(String::as_str) != Some(epoch) {
        options.remove("incoming-only-initialized");
        apply_default_lock(options);
        options.insert("receiver-install-id".into(), epoch.into());
    }
}

pub(super) fn relock_machine_policy(mut policy: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let valid = policy.get("schema").and_then(|v| v.as_u64()) == Some(1)
        && policy.get("locked").and_then(|v| v.as_bool()).is_some()
        && policy.get("passwordHash").and_then(|v| v.as_str())
            .map_or(false, |v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()));
    if !valid { anyhow::bail!("Invalid device receiver policy; cannot reset installation defaults"); }
    let revision = policy.get("revision").and_then(|v| v.as_u64())
        .and_then(|v| v.checked_add(1)).ok_or_else(|| anyhow::anyhow!("Invalid device policy revision"))?;
    policy["locked"] = true.into();
    policy["revision"] = revision.into();
    Ok(policy)
}

pub(super) fn explicitly_unlocked(state: &str) -> bool {
    matches!(state, "unlocked" | "Y")
}

pub(super) fn apply_default_lock(options: &mut HashMap<String, String>) {
    if explicitly_unlocked(options.get("incoming-only-initialized").map(String::as_str).unwrap_or("")) { return; }
    options.insert("incoming-only".into(), "Y".into());
    if options.get("incoming-only-password").map_or(true, String::is_empty) {
        options.insert("incoming-only-password".into(),
            "b008f337c227dcb4fa0fa4b1e9b915dd24a34e698b6739236f96b29fa9d2f532".into());
    }
    options.insert("incoming-only-initialized".into(), "locked".into());
}

#[cfg(windows)]
pub(super) fn machine_option(key: &str) -> Option<String> {
    if !matches!(key, "incoming-only" | "incoming-only-password" | "incoming-only-initialized" | "incoming-only-scope") || installed_profile().is_none() { return None; }
    use winapi::um::winreg::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY};
    let path: Vec<u16> = "Software\\SubnetDesk\\DevicePolicy\0".encode_utf16().collect();
    let name: Vec<u16> = "ReceiverPolicy\0".encode_utf16().collect();
    let mut buffer = [0u16; 2048]; let mut bytes = (buffer.len() * 2) as u32;
    let status = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, path.as_ptr(), name.as_ptr(), RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, std::ptr::null_mut(), buffer.as_mut_ptr().cast(), &mut bytes) };
    // Only missing keys mean unmanaged. Unreadable/malformed policies fail closed.
    if status == 2 || status == 3 { return if key == "incoming-only-scope" { Some("profile".into()) } else { None }; }
    let text = buffer.iter().position(|c| *c == 0).and_then(|length| String::from_utf16(&buffer[..length]).ok());
    let policy = if status == 0 { text.as_deref().and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok()) } else { None };
    Some(machine_policy_value(key, policy.as_ref()))
}

fn machine_policy_value(key: &str, policy: Option<&serde_json::Value>) -> String {
    let valid = policy.filter(|p| p.get("schema").and_then(|v| v.as_u64()) == Some(1)
        && p.get("locked").and_then(|v| v.as_bool()).is_some()
        && p.get("passwordHash").and_then(|v| v.as_str()).map_or(false, |v| v.len() == 64 && v.bytes().all(|c| c.is_ascii_hexdigit())));
    let locked = valid.and_then(|p| p.get("locked")).and_then(|v| v.as_bool()).unwrap_or(true);
    match key {
        "incoming-only-scope" => "device".into(),
        "incoming-only" => if locked { "Y" } else { "" }.into(),
        "incoming-only-initialized" => if locked { "locked" } else { "unlocked" }.into(),
        "incoming-only-password" if locked => valid.and_then(|p| p.get("passwordHash")).and_then(|v| v.as_str()).unwrap_or("invalid-managed-policy").to_ascii_lowercase(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    #[test]
    fn every_new_install_epoch_relocks_existing_profiles_but_restart_does_not() {
        let mut user = HashMap::from([
            ("incoming-only-initialized".into(), "unlocked".into()),
            ("incoming-only-password".into(), "existing-verifier".into()),
            ("unrelated-option".into(), "keep".into()),
        ]);
        apply_install_lock(&mut user, "install-one");
        assert_eq!(user["incoming-only"], "Y");
        assert_eq!(user["incoming-only-password"], "existing-verifier");
        assert_eq!(user["unrelated-option"], "keep");
        user.insert("incoming-only-initialized".into(), "unlocked".into());
        user.insert("incoming-only".into(), "".into());
        apply_install_lock(&mut user, "install-one");
        assert_eq!(user["incoming-only-initialized"], "unlocked");
        let mut other_user = user.clone();
        for account in [&mut user, &mut other_user] {
            apply_install_lock(account, "install-two");
            assert_eq!(account["incoming-only-initialized"], "locked");
            assert_eq!(account["incoming-only"], "Y");
        }
    }
    #[test]
    fn reinstall_relocks_device_policy_without_replacing_its_password() {
        let password = "a".repeat(64);
        let original = serde_json::json!({"schema":1,"locked":false,"passwordHash":password,"revision":9});
        let locked = relock_machine_policy(original).unwrap();
        assert_eq!(locked["locked"], true);
        assert_eq!(locked["passwordHash"], password);
        assert_eq!(locked["revision"], 10);
        assert!(relock_machine_policy(serde_json::json!({"schema":1})).is_err());
    }
    #[test]
    fn installation_profiles_are_separate_and_cannot_escape_root() {
        let root = Path::new("config").to_path_buf();
        let first = profile_path(root.clone(), "00000000-0000-4000-8000-000000000001").unwrap();
        let next = profile_path(root.clone(), "00000000-0000-4000-8000-000000000002").unwrap();
        assert_ne!(first, next);
        assert!(first.starts_with(&root));
        assert!(profile_path(root, "../../old-profile").is_none());
    }
    #[test]
    fn only_explicit_unlock_survives_startup() {
        for state in ["", "locked", "initialized", "true"] { assert!(!explicitly_unlocked(state)); }
        for state in ["unlocked", "Y"] { assert!(explicitly_unlocked(state)); }
    }
    #[test]
    fn device_policy_overrides_each_accounts_legacy_state() {
        let locked=serde_json::json!({"schema":1,"locked":true,"passwordHash":"a".repeat(64)});
        let unlocked=serde_json::json!({"schema":1,"locked":false,"passwordHash":"a".repeat(64)});
        for _legacy_state in ["locked","unlocked",""] {
            assert_eq!(machine_policy_value("incoming-only",Some(&locked)),"Y");
            assert_eq!(machine_policy_value("incoming-only-initialized",Some(&unlocked)),"unlocked");
            assert_eq!(machine_policy_value("incoming-only",Some(&unlocked)),"");
            assert_eq!(machine_policy_value("incoming-only-password",Some(&unlocked)),"");
            assert_eq!(machine_policy_value("incoming-only-scope",Some(&locked)),"device");
        }
    }
    #[test]
    fn unreadable_or_invalid_device_policy_never_unlocks() {
        for policy in [None,Some(serde_json::json!({"schema":2,"locked":false})),Some(serde_json::json!({"schema":1,"locked":false,"passwordHash":"invalid"}))] {
            assert_eq!(machine_policy_value("incoming-only",policy.as_ref()),"Y");
        }
    }
    #[test]
    fn lock_unlock_and_relock_preserve_the_password_and_explicit_choice() {
        let mut options = HashMap::new();
        apply_default_lock(&mut options);
        assert_eq!(options.get("incoming-only").map(String::as_str), Some("Y"));
        options.insert("incoming-only-password".into(), "custom-hash".into());
        apply_default_lock(&mut options);
        assert_eq!(options.get("incoming-only-password").map(String::as_str), Some("custom-hash"));
        options.remove("incoming-only");
        options.remove("incoming-only-password");
        options.insert("incoming-only-initialized".into(), "unlocked".into());
        let unlocked = options.clone();
        apply_default_lock(&mut options);
        assert_eq!(options, unlocked);
        options.insert("incoming-only-initialized".into(), "locked".into());
        options.insert("incoming-only-password".into(), "new-hash".into());
        apply_default_lock(&mut options);
        assert_eq!(options.get("incoming-only-password").map(String::as_str), Some("new-hash"));
        assert_eq!(options.get("incoming-only").map(String::as_str), Some("Y"));
    }
}
