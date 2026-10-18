//! The OS credential store (macOS Keychain, Windows Credential Manager,
//! Linux Secret Service), used for saved logins and the `keychain` consumer.
//!
//! - `REKEY_DISABLE_KEYCHAIN=1` turns it off entirely: nothing is read
//!   or written (useful in CI, where there is no keychain).
//! - Debug builds only: `REKEY_TEST_CREDSTORE=<file>` swaps in a
//!   plaintext JSON file so tests never touch the real keychain. Release
//!   builds don't contain this backend at all.

/// Service name under which saved provider logins live.
pub const LOGIN_SERVICE: &str = "rekey-login";

enum Backend {
    Disabled,
    #[cfg(debug_assertions)]
    File(std::path::PathBuf),
    #[cfg(feature = "os-keyring")]
    Os,
    #[cfg(not(feature = "os-keyring"))]
    Unsupported,
}

fn backend() -> Backend {
    if std::env::var_os("REKEY_DISABLE_KEYCHAIN").is_some_and(|v| !v.is_empty()) {
        return Backend::Disabled;
    }
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("REKEY_TEST_CREDSTORE") {
        return Backend::File(path.into());
    }
    #[cfg(feature = "os-keyring")]
    return Backend::Os;
    #[cfg(not(feature = "os-keyring"))]
    Backend::Unsupported
}

/// Whether saving credentials can work in this build/environment.
pub fn available() -> bool {
    match backend() {
        Backend::Disabled => false,
        #[cfg(not(feature = "os-keyring"))]
        Backend::Unsupported => false,
        #[allow(unreachable_patterns)]
        _ => true,
    }
}

/// Where credentials are saved, for messages ("saved to your macOS Keychain").
pub fn place() -> &'static str {
    if cfg!(target_os = "macos") {
        "your macOS Keychain"
    } else if cfg!(windows) {
        "Windows Credential Manager"
    } else {
        "your system keyring"
    }
}

/// Read a value. Missing entries and unavailable stores both read as `None`.
pub fn get(service: &str, account: &str) -> Option<String> {
    match backend() {
        Backend::Disabled => None,
        #[cfg(debug_assertions)]
        Backend::File(path) => file::load(&path).remove(&key(service, account)),
        #[cfg(feature = "os-keyring")]
        Backend::Os => keyring::Entry::new(service, account)
            .and_then(|e| e.get_password())
            .ok(),
        #[cfg(not(feature = "os-keyring"))]
        Backend::Unsupported => None,
    }
}

pub fn set(service: &str, account: &str, value: &str) -> Result<(), String> {
    match backend() {
        Backend::Disabled => Err("the keychain is disabled (REKEY_DISABLE_KEYCHAIN)".into()),
        #[cfg(debug_assertions)]
        Backend::File(path) => {
            let mut map = file::load(&path);
            map.insert(key(service, account), value.to_string());
            file::save(&path, &map)
        }
        #[cfg(feature = "os-keyring")]
        Backend::Os => keyring::Entry::new(service, account)
            .and_then(|e| e.set_password(value))
            .map_err(|e| e.to_string()),
        #[cfg(not(feature = "os-keyring"))]
        Backend::Unsupported => {
            Err("this build has no keychain support (built without os-keyring)".into())
        }
    }
}

/// Remove a value. Removing something that isn't there is not an error.
pub fn delete(service: &str, account: &str) -> Result<(), String> {
    match backend() {
        Backend::Disabled => Ok(()),
        #[cfg(debug_assertions)]
        Backend::File(path) => {
            let mut map = file::load(&path);
            map.remove(&key(service, account));
            file::save(&path, &map)
        }
        #[cfg(feature = "os-keyring")]
        Backend::Os => {
            match keyring::Entry::new(service, account).and_then(|e| e.delete_password()) {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
        #[cfg(not(feature = "os-keyring"))]
        Backend::Unsupported => Ok(()),
    }
}

#[cfg(debug_assertions)]
fn key(service: &str, account: &str) -> String {
    format!("{service}/{account}")
}

#[cfg(debug_assertions)]
mod file {
    use std::collections::BTreeMap;
    use std::path::Path;

    pub fn load(path: &Path) -> BTreeMap<String, String> {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(path: &Path, map: &BTreeMap<String, String>) -> Result<(), String> {
        let text = serde_json::to_string_pretty(map).map_err(|e| e.to_string())?;
        crate::consumers::write_private(path, text.as_bytes()).map_err(|e| e.to_string())
    }
}
