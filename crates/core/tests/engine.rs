use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use keyrotator_core::connector::Connector;
use keyrotator_core::models::{NewCredential, ProviderKind, RotationError, RotationStyle, Secret};
use keyrotator_core::RotationEngine;

/// Records call order so we can assert the engine's sequencing and rollback.
struct MockConnector {
    style: RotationStyle,
    calls: Arc<Mutex<Vec<String>>>,
    fail_verify: bool,
}

impl MockConnector {
    fn new(style: RotationStyle, fail_verify: bool) -> (Arc<Self>, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let c = Arc::new(Self {
            style,
            calls: calls.clone(),
            fail_verify,
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

fn sample() -> Secret {
    Secret::new(ProviderKind::Aws, "OLDID0000000000000", "test", "ci-user")
}

#[tokio::test]
async fn overlap_happy_path_order() {
    let (mock, calls) = MockConnector::new(RotationStyle::Overlap, false);
    let engine = RotationEngine::new(vec![mock]);
    let new_id = engine.rotate(&sample(), true).await.unwrap();

    assert_eq!(new_id, "NEWID000000000000");
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
async fn overlap_rollback_spares_old_key() {
    let (mock, calls) = MockConnector::new(RotationStyle::Overlap, true);
    let engine = RotationEngine::new(vec![mock]);
    let err = engine.rotate(&sample(), false).await;
    assert!(err.is_err());

    let log = calls.lock().unwrap();
    // New key destroyed, old key never touched.
    assert!(log.contains(&"delete:NEWID000000000000".to_string()));
    assert!(!log.iter().any(|c| c.starts_with("deactivate:OLD")));
}

#[tokio::test]
async fn ephemeral_mints_and_verifies_only() {
    let (mock, calls) = MockConnector::new(RotationStyle::Ephemeral, false);
    let engine = RotationEngine::new(vec![mock]);
    let new_id = engine.rotate(&sample(), false).await.unwrap();

    assert_eq!(new_id, "NEWID000000000000");
    // Ephemeral tokens expire on their own — mint + verify, nothing destructive.
    assert_eq!(*calls.lock().unwrap(), vec!["create", "verify"]);
}

#[tokio::test]
async fn atomic_never_touches_old_key() {
    let (mock, calls) = MockConnector::new(RotationStyle::AtomicRotate, false);
    let engine = RotationEngine::new(vec![mock]);
    let new_id = engine.rotate(&sample(), false).await.unwrap();

    assert_eq!(new_id, "NEWID000000000000");
    let log = calls.lock().unwrap();
    // Atomic providers revoke the old token themselves — no deactivate/delete.
    assert_eq!(*log, vec!["create", "verify"]);
}
