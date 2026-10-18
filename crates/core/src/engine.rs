use std::collections::HashMap;
use std::sync::Arc;

use crate::connector::Connector;
use crate::consumers::ConsumerUpdater;
use crate::models::{
    NewCredential, ProviderKind, RotationError, RotationStage, RotationStyle, Secret,
};
use crate::secrets::{InMemoryStore, SecretStore};

/// Progress callback type. Receives the secret id, stage, and a message.
pub type ProgressFn = Arc<dyn Fn(uuid::Uuid, RotationStage, &str) + Send + Sync>;

pub struct RotationEngine {
    connectors: HashMap<ProviderKind, Arc<dyn Connector>>,
    updater: ConsumerUpdater,
    store: Arc<dyn SecretStore>,
    on_progress: Option<ProgressFn>,
}

impl RotationEngine {
    pub fn new(connectors: Vec<Arc<dyn Connector>>) -> Self {
        let map = connectors.into_iter().map(|c| (c.kind(), c)).collect();
        Self {
            connectors: map,
            updater: ConsumerUpdater,
            store: Arc::new(InMemoryStore::default()),
            on_progress: None,
        }
    }

    pub fn with_store(mut self, store: Arc<dyn SecretStore>) -> Self {
        self.store = store;
        self
    }

    pub fn on_progress(mut self, f: ProgressFn) -> Self {
        self.on_progress = Some(f);
        self
    }

    fn emit(&self, secret: &Secret, stage: RotationStage, msg: &str) {
        if let Some(cb) = &self.on_progress {
            cb(secret.id, stage, msg);
        }
    }

    /// Rotate one secret end to end. Returns the new external id on success.
    pub async fn rotate(
        &self,
        secret: &Secret,
        delete_old_now: bool,
    ) -> Result<String, RotationError> {
        let connector = self.connectors.get(&secret.provider).ok_or_else(|| {
            RotationError::NotImplemented(format!(
                "no connector for {}",
                secret.provider.display_name()
            ))
        })?;

        match connector.rotation_style() {
            RotationStyle::Overlap => self.rotate_overlap(connector, secret, delete_old_now).await,
            RotationStyle::AtomicRotate => self.rotate_atomic(connector, secret).await,
            RotationStyle::Ephemeral => self.rotate_ephemeral(connector, secret).await,
            RotationStyle::Manual => {
                // Nothing destructive: this provider can't mint a key via API.
                let hint = connector.manual_rotation_hint().unwrap_or_else(|| {
                    format!(
                        "{} keys must be created manually; the tool can revoke the old one once you have the new one.",
                        secret.provider.display_name()
                    )
                });
                self.emit(secret, RotationStage::Failed, &hint);
                Err(RotationError::ManualActionRequired(hint))
            }
        }
    }

    /// Overlap: old key stays live until the new one is proven. Clean rollback.
    async fn rotate_overlap(
        &self,
        connector: &Arc<dyn Connector>,
        secret: &Secret,
        delete_old_now: bool,
    ) -> Result<String, RotationError> {
        self.emit(secret, RotationStage::Creating, "Creating new credential…");
        let cred = connector.create(secret).await?;

        // Steps that, if they fail, let us roll back by destroying the new key.
        if let Err(e) = self.cutover_and_verify(connector, secret, &cred).await {
            self.emit(
                secret,
                RotationStage::RolledBack,
                &format!("Rolling back: {e}"),
            );
            let _ = connector.delete_old(&cred.external_id).await; // destroy new key
            return Err(e);
        }

        let _ = self.store.set(
            &store_key(secret.provider, &cred.external_id),
            &cred.secret_value,
        );

        self.emit(
            secret,
            RotationStage::DeactivatingOld,
            "Deactivating old credential…",
        );
        connector.deactivate_old(&secret.external_id).await?;

        if delete_old_now {
            self.emit(
                secret,
                RotationStage::DeletingOld,
                "Deleting old credential…",
            );
            connector.delete_old(&secret.external_id).await?;
            let _ = self
                .store
                .delete(&store_key(secret.provider, &secret.external_id));
        }

        self.emit(secret, RotationStage::Done, "Rotated successfully.");
        Ok(cred.external_id)
    }

    /// Atomic: the provider mints the new secret and revokes the old one in one
    /// call. No rollback to the old secret is possible — if verify fails after
    /// consumers are updated, we surface it loudly so the user re-rotates.
    async fn rotate_atomic(
        &self,
        connector: &Arc<dyn Connector>,
        secret: &Secret,
    ) -> Result<String, RotationError> {
        self.emit(
            secret,
            RotationStage::Creating,
            "Rotating (provider revokes old token immediately)…",
        );
        let cred = connector.create(secret).await?;

        // Old token is already dead at this point. Get consumers onto the new
        // one as fast as possible, then verify.
        let _ = self.store.set(
            &store_key(secret.provider, &cred.external_id),
            &cred.secret_value,
        );

        self.emit(
            secret,
            RotationStage::UpdatingConsumers,
            "Updating consumers…",
        );
        for consumer in &secret.consumers {
            self.updater.update(consumer, &cred).await?;
        }

        self.emit(secret, RotationStage::Verifying, "Verifying new token…");
        if let Err(e) = connector.verify(&cred).await {
            // Can't restore the old token; make the failure unmissable.
            self.emit(
                secret,
                RotationStage::Failed,
                &format!("New token failed verification and the old one is already revoked: {e}"),
            );
            return Err(RotationError::VerificationFailed(format!(
                "atomic rotation left no working token — re-run rotate for {}: {e}",
                secret.label
            )));
        }

        self.emit(secret, RotationStage::Done, "Rotated successfully.");
        Ok(cred.external_id)
    }

    /// Ephemeral: mint a fresh short-lived token, push it to consumers, verify.
    /// Nothing to revoke — the previous token expires on its own.
    async fn rotate_ephemeral(
        &self,
        connector: &Arc<dyn Connector>,
        secret: &Secret,
    ) -> Result<String, RotationError> {
        self.emit(
            secret,
            RotationStage::Creating,
            "Minting short-lived token…",
        );
        let cred = connector.create(secret).await?;

        let _ = self.store.set(
            &store_key(secret.provider, &cred.external_id),
            &cred.secret_value,
        );

        self.emit(
            secret,
            RotationStage::UpdatingConsumers,
            "Updating consumers…",
        );
        for consumer in &secret.consumers {
            self.updater.update(consumer, &cred).await?;
        }

        self.emit(secret, RotationStage::Verifying, "Verifying new token…");
        connector.verify(&cred).await?;

        self.emit(secret, RotationStage::Done, "Minted and verified.");
        Ok(cred.external_id)
    }

    async fn cutover_and_verify(
        &self,
        connector: &Arc<dyn Connector>,
        secret: &Secret,
        cred: &NewCredential,
    ) -> Result<(), RotationError> {
        self.emit(
            secret,
            RotationStage::UpdatingConsumers,
            &format!("Updating {} consumer(s)…", secret.consumers.len()),
        );
        for consumer in &secret.consumers {
            self.updater.update(consumer, cred).await?;
        }
        self.emit(
            secret,
            RotationStage::Verifying,
            "Verifying new credential…",
        );
        connector.verify(cred).await
    }

    /// Rotate many secrets concurrently. Returns a map of secret id → result.
    pub async fn rotate_all(
        &self,
        secrets: &[Secret],
    ) -> HashMap<uuid::Uuid, Result<String, RotationError>> {
        let jobs = secrets
            .iter()
            .map(|s| async move { (s.id, self.rotate(s, false).await) });
        futures::future::join_all(jobs).await.into_iter().collect()
    }
}

fn store_key(provider: ProviderKind, external_id: &str) -> String {
    format!("{}:{}", provider.display_name(), external_id)
}
