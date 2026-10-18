use async_trait::async_trait;

use crate::models::{NewCredential, ProviderKind, RotationError, RotationStyle, Secret};

/// The uniform interface every provider implements. The engine only talks to
/// this, so adding a provider is just a new type.
///
/// Only operates on accounts the user owns or administers — each method acts
/// through the user's authorized session/token, never on a key merely seen.
///
/// For `RotationStyle::AtomicRotate` providers, `create` performs the whole
/// rotate (new secret out, old one revoked by the provider), and
/// `deactivate_old` / `delete_old` are no-ops. For `Overlap`, `create` only
/// mints the new secret and the engine later calls deactivate/delete.
#[async_trait]
pub trait Connector: Send + Sync {
    fn kind(&self) -> ProviderKind;

    fn rotation_style(&self) -> RotationStyle;

    /// For `RotationStyle::Manual` providers: what the user must do by hand to
    /// mint the new secret (e.g. a console URL). Ignored for other styles.
    fn manual_rotation_hint(&self) -> Option<String> {
        None
    }

    /// Verify stored auth works and the user can manage keys.
    async fn connect(&self) -> Result<(), RotationError>;

    /// Enumerate the account's current keys as managed Secrets.
    async fn list_keys(&self) -> Result<Vec<Secret>, RotationError>;

    /// Mint the new credential for the same principal as `secret`.
    async fn create(&self, secret: &Secret) -> Result<NewCredential, RotationError>;

    /// Prove the new credential actually authenticates.
    async fn verify(&self, credential: &NewCredential) -> Result<(), RotationError>;

    /// Disable the old credential but keep it recoverable. (Overlap only.)
    async fn deactivate_old(&self, _external_id: &str) -> Result<(), RotationError> {
        Ok(())
    }

    /// Permanently remove the old credential. (Overlap only; after grace period.)
    async fn delete_old(&self, _external_id: &str) -> Result<(), RotationError> {
        Ok(())
    }
}
