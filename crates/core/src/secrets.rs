use std::collections::HashMap;
use std::sync::Mutex;

/// Stores secret material out of plaintext files and logs.
pub trait SecretStore: Send + Sync {
    fn set(&self, account: &str, value: &str) -> Result<(), String>;
    fn get(&self, account: &str) -> Result<Option<String>, String>;
    fn delete(&self, account: &str) -> Result<(), String>;
}

/// Process-local, in-memory store. The default so the crate builds and tests
/// on bare Linux/CI. NOT for production — use the OS keyring store instead.
#[derive(Default)]
pub struct InMemoryStore {
    inner: Mutex<HashMap<String, String>>,
}

impl SecretStore for InMemoryStore {
    fn set(&self, account: &str, value: &str) -> Result<(), String> {
        self.inner
            .lock()
            .unwrap()
            .insert(account.into(), value.into());
        Ok(())
    }
    fn get(&self, account: &str) -> Result<Option<String>, String> {
        Ok(self.inner.lock().unwrap().get(account).cloned())
    }
    fn delete(&self, account: &str) -> Result<(), String> {
        self.inner.lock().unwrap().remove(account);
        Ok(())
    }
}

/// OS-backed store: macOS Keychain, Windows Credential Manager, or libsecret.
/// Compiled only with `--features os-keyring`.
#[cfg(feature = "os-keyring")]
pub struct OsKeyringStore {
    service: String,
}

#[cfg(feature = "os-keyring")]
impl OsKeyringStore {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

#[cfg(feature = "os-keyring")]
impl SecretStore for OsKeyringStore {
    fn set(&self, account: &str, value: &str) -> Result<(), String> {
        keyring::Entry::new(&self.service, account)
            .and_then(|e| e.set_password(value))
            .map_err(|e| e.to_string())
    }
    fn get(&self, account: &str) -> Result<Option<String>, String> {
        match keyring::Entry::new(&self.service, account).and_then(|e| e.get_password()) {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    fn delete(&self, account: &str) -> Result<(), String> {
        match keyring::Entry::new(&self.service, account).and_then(|e| e.delete_credential()) {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}
