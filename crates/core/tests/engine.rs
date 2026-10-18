use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rekey_core::connector::Connector;
use rekey_core::models::{
    Consumer, NewCredential, OldKeyState, ProviderKind, RotationError, RotationStyle, Secret,
};
use rekey_core::RotationEngine;

/// Records call order so we can assert the engine's sequencing and rollback.
struct MockConnector {
    style: RotationStyle,
    calls: Arc<Mutex<Vec<String>>>,
    fail_verify: bool,
    deactivate: bool,
}

impl MockConnector {
    fn new(style: RotationStyle, fail_verify: bool) -> (Arc<Self>, Arc<Mutex<Vec<String>>>) {
        Self::build(style, fail_verify, true)
    }
    fn build(
        style: RotationStyle,
        fail_verify: bool,
        deactivate: bool,
    ) -> (Arc<Self>, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let c = Arc::new(Self {
            style,
            calls: calls.clone(),
            fail_verify,
            deactivate,
        });
        (c, calls)
    }
    fn log(&self, s: &str) {
        self.calls.lock().unwrap().push(s.to_string());
    }
}

#[async_trait]
impl Connector for MockConnector {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Aws
    }
    fn rotation_style(&self) -> RotationStyle {
        self.style
    }
    fn supports_deactivate(&self) -> bool {
        self.deactivate
    }

    async fn connect(&self) -> Result<(), RotationError> {
        Ok(())
    }
    async fn list_keys(&self) -> Result<Vec<Secret>, RotationError> {
        Ok(vec![])
    }

    async fn create(&self, _s: &Secret) -> Result<NewCredential, RotationError> {
        self.log("create");
        Ok(NewCredential::new("NEWID000000000000", "secret-material"))
    }
    async fn verify(&self, _c: &NewCredential) -> Result<(), RotationError> {
        self.log("verify");
        if self.fail_verify {
            Err(RotationError::VerificationFailed("forced".into()))
        } else {
            Ok(())
        }
    }
    async fn deactivate_old(&self, id: &str) -> Result<(), RotationError> {
        self.log(&format!("deactivate:{id}"));
        Ok(())
    }
    async fn delete_old(&self, id: &str) -> Result<(), RotationError> {
        self.log(&format!("delete:{id}"));
        Ok(())
    }
}

fn tmpdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("kr-engine-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn sample(consumers: Vec<Consumer>) -> Secret {
    let mut s = Secret::new(ProviderKind::Aws, "OLDID0000000000000", "test", "ci-user");
    s.consumers = consumers;
    s
}

/// A consumer that always succeeds and returns the value to the caller.
fn revealed() -> Secret {
    sample(vec![Consumer::Reveal])
}

/// A consumer that always fails: a file inside a directory that doesn't exist.
fn broken() -> Consumer {
    Consumer::File {
        path: "/nonexistent-rekey-dir/x/secret".into(),
    }
}

#[tokio::test]
async fn refuses_to_rotate_without_a_destination() {
    for style in [
        RotationStyle::Overlap,
        RotationStyle::AtomicRotate,
        RotationStyle::Ephemeral,
    ] {
        let (mock, calls) = MockConnector::new(style, false);
        let engine = RotationEngine::new(vec![mock]);
        let err = engine.rotate(&sample(vec![]), true).await.unwrap_err();
        assert!(matches!(err, RotationError::NoDestination(_)), "{err}");
        // Nothing was minted or revoked.
        assert!(calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn overlap_happy_path_order() {
    let (mock, calls) = MockConnector::new(RotationStyle::Overlap, false);
    let engine = RotationEngine::new(vec![mock]);
    let out = engine.rotate(&revealed(), true).await.unwrap();

    assert_eq!(out.new_external_id, "NEWID000000000000");
    assert_eq!(out.revealed_secret.as_deref(), Some("secret-material"));
    assert_eq!(out.old_key, OldKeyState::Deleted);
    assert!(out.is_clean());
    assert_eq!(
        *calls.lock().unwrap(),
        vec![
            "create",
            "verify",
            "deactivate:OLDID0000000000000",
            "delete:OLDID0000000000000",
        ]
    );
}

#[tokio::test]
async fn overlap_without_disabled_state_reports_old_key_still_active() {
    let (mock, calls) = MockConnector::build(RotationStyle::Overlap, false, false);
    let engine = RotationEngine::new(vec![mock]);
    let out = engine.rotate(&revealed(), false).await.unwrap();

    assert_eq!(out.old_key, OldKeyState::StillActive);
    assert_eq!(*calls.lock().unwrap(), vec!["create", "verify"]);
}

#[tokio::test]
async fn overlap_verifies_before_touching_consumers() {
    let dir = tmpdir();
    let env = dir.join(".env");
    std::fs::write(&env, "KEY=old\n").unwrap();

    let (mock, calls) = MockConnector::new(RotationStyle::Overlap, true);
    let engine = RotationEngine::new(vec![mock]);
    let secret = sample(vec![Consumer::DotEnvFile {
        path: env.to_string_lossy().into(),
        variable: "KEY".into(),
        id_variable: None,
    }]);
    assert!(engine.rotate(&secret, false).await.is_err());

    // Verify failed: the .env file still has the old (working) key…
    assert_eq!(std::fs::read_to_string(&env).unwrap(), "KEY=old\n");
    // …the new key was destroyed and the old one never touched.
    let log = calls.lock().unwrap();
    assert!(log.contains(&"delete:NEWID000000000000".to_string()));
    assert!(!log.iter().any(|c| c.contains("OLDID")));
}

#[tokio::test]
async fn overlap_rolls_back_when_every_consumer_fails() {
    let (mock, calls) = MockConnector::new(RotationStyle::Overlap, false);
    let engine = RotationEngine::new(vec![mock]);
    let err = engine.rotate(&sample(vec![broken()]), true).await;
    assert!(matches!(err, Err(RotationError::ConsumerUpdate(_))));

    let log = calls.lock().unwrap();
    assert!(log.contains(&"delete:NEWID000000000000".to_string()));
    assert!(!log.iter().any(|c| c.contains("OLDID")));
}

#[tokio::test]
async fn overlap_partial_failure_keeps_both_keys_alive() {
    let dir = tmpdir();
    let good = dir.join("good.secret");
    let (mock, calls) = MockConnector::new(RotationStyle::Overlap, false);
    let engine = RotationEngine::new(vec![mock]);
    let secret = sample(vec![
        Consumer::File {
            path: good.to_string_lossy().into(),
        },
        broken(),
    ]);
    let out = engine.rotate(&secret, true).await.unwrap();

    assert!(!out.is_clean());
    assert_eq!(out.old_key, OldKeyState::StillActive);
    assert_eq!(out.updated_consumers.len(), 1);
    assert_eq!(out.failed_consumers.len(), 1);
    assert_eq!(std::fs::read_to_string(&good).unwrap(), "secret-material\n");
    // Neither key was deactivated or deleted — even with --delete-old-now.
    let log = calls.lock().unwrap();
    assert!(!log
        .iter()
        .any(|c| c.starts_with("deactivate") || c.starts_with("delete")));
}

#[tokio::test]
async fn ephemeral_mints_and_verifies_only() {
    let (mock, calls) = MockConnector::new(RotationStyle::Ephemeral, false);
    let engine = RotationEngine::new(vec![mock]);
    let out = engine.rotate(&revealed(), false).await.unwrap();

    assert_eq!(out.new_external_id, "NEWID000000000000");
    assert_eq!(out.old_key, OldKeyState::NotApplicable);
    // Ephemeral tokens expire on their own — mint + verify, nothing destructive.
    assert_eq!(*calls.lock().unwrap(), vec!["create", "verify"]);
}

#[tokio::test]
async fn atomic_never_touches_old_key() {
    let (mock, calls) = MockConnector::new(RotationStyle::AtomicRotate, false);
    let engine = RotationEngine::new(vec![mock]);
    let out = engine.rotate(&revealed(), false).await.unwrap();

    assert_eq!(out.new_external_id, "NEWID000000000000");
    assert_eq!(out.old_key, OldKeyState::Revoked);
    assert_eq!(out.revealed_secret.as_deref(), Some("secret-material"));
    // Atomic providers revoke the old token themselves — no deactivate/delete.
    assert_eq!(*calls.lock().unwrap(), vec!["create", "verify"]);
}

#[tokio::test]
async fn atomic_writes_rescue_file_when_every_consumer_fails() {
    let dir = tmpdir();
    let (mock, _) = MockConnector::new(RotationStyle::AtomicRotate, false);
    let engine = RotationEngine::new(vec![mock]).rescue_dir(&dir);
    let out = engine.rotate(&sample(vec![broken()]), false).await.unwrap();

    assert!(!out.is_clean());
    let rescue = out.rescue_file.expect("rescue file written");
    assert_eq!(
        std::fs::read_to_string(&rescue).unwrap(),
        "secret-material\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&rescue).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[tokio::test]
async fn atomic_verify_failure_is_reported_not_swallowed() {
    let (mock, _) = MockConnector::new(RotationStyle::AtomicRotate, true);
    let engine = RotationEngine::new(vec![mock]);
    let out = engine.rotate(&revealed(), false).await.unwrap();
    // The value is still handed back so the user isn't locked out.
    assert_eq!(out.revealed_secret.as_deref(), Some("secret-material"));
    assert!(out
        .problems
        .iter()
        .any(|p| p.contains("failed verification")));
}

#[tokio::test]
async fn retire_deactivates_then_deletes() {
    let (mock, calls) = MockConnector::new(RotationStyle::Overlap, false);
    let engine = RotationEngine::new(vec![mock]);
    let state = engine
        .retire(ProviderKind::Aws, "OLD", false)
        .await
        .unwrap();
    assert_eq!(state, OldKeyState::Deactivated);
    let state = engine.retire(ProviderKind::Aws, "OLD", true).await.unwrap();
    assert_eq!(state, OldKeyState::Deleted);
    assert_eq!(
        *calls.lock().unwrap(),
        vec!["deactivate:OLD", "deactivate:OLD", "delete:OLD"]
    );
}

#[tokio::test]
async fn retire_deletes_when_provider_has_no_disabled_state() {
    let (mock, calls) = MockConnector::build(RotationStyle::Overlap, false, false);
    let engine = RotationEngine::new(vec![mock]);
    let state = engine
        .retire(ProviderKind::Aws, "OLD", false)
        .await
        .unwrap();
    assert_eq!(state, OldKeyState::Deleted);
    assert_eq!(*calls.lock().unwrap(), vec!["delete:OLD"]);
}

#[tokio::test]
async fn retire_refuses_atomic_providers() {
    let (mock, calls) = MockConnector::new(RotationStyle::AtomicRotate, false);
    let engine = RotationEngine::new(vec![mock]);
    assert!(engine.retire(ProviderKind::Aws, "OLD", true).await.is_err());
    assert!(calls.lock().unwrap().is_empty());
}
