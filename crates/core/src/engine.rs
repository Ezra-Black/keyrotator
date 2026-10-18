use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::connector::Connector;
use crate::consumers::{write_private, ConsumerUpdater};
use crate::models::{
    Consumer, NewCredential, OldKeyState, ProviderKind, RotationError, RotationOutcome,
    RotationStage, RotationStyle, Secret,
};

/// Progress callback type. Receives the secret id, stage, and a message.
pub type ProgressFn = Arc<dyn Fn(uuid::Uuid, RotationStage, &str) + Send + Sync>;

/// Drives a rotation end to end.
///
/// Contract: `rotate` returns `Err` only when nothing changed — the old key is
/// untouched and any new key was destroyed. Once the provider's state has
/// changed it returns `Ok(RotationOutcome)`, whose `problems` say what still
/// needs attention. The new secret is always delivered to at least one
/// consumer before anything irreversible happens.
pub struct RotationEngine {
    connectors: HashMap<ProviderKind, Arc<dyn Connector>>,
    updater: ConsumerUpdater,
    on_progress: Option<ProgressFn>,
    rescue_dir: PathBuf,
}

impl RotationEngine {
    pub fn new(connectors: Vec<Arc<dyn Connector>>) -> Self {
        let map = connectors.into_iter().map(|c| (c.kind(), c)).collect();
        Self {
            connectors: map,
            updater: ConsumerUpdater,
            on_progress: None,
            rescue_dir: PathBuf::from("."),
        }
    }

    pub fn on_progress(mut self, f: ProgressFn) -> Self {
        self.on_progress = Some(f);
        self
    }

    /// Where to write a last-resort copy of a secret when an irreversible
    /// rotation couldn't deliver it to any consumer. Defaults to the cwd.
    pub fn rescue_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.rescue_dir = dir.into();
        self
    }

    fn emit(&self, secret: &Secret, stage: RotationStage, msg: &str) {
        if let Some(cb) = &self.on_progress {
            cb(secret.id, stage, msg);
        }
    }

    fn connector(&self, provider: ProviderKind) -> Result<&Arc<dyn Connector>, RotationError> {
        self.connectors.get(&provider).ok_or_else(|| {
            RotationError::NotImplemented(format!("no connector for {}", provider.display_name()))
        })
    }

    /// Rotate one secret end to end.
    pub async fn rotate(
        &self,
        secret: &Secret,
        delete_old_now: bool,
    ) -> Result<RotationOutcome, RotationError> {
        let connector = self.connector(secret.provider)?;

        if connector.rotation_style() == RotationStyle::Manual {
            // Nothing destructive: this provider can't mint a key via API.
            let hint = connector.manual_rotation_hint().unwrap_or_else(|| {
                format!(
                    "{} keys must be created manually; run `retire` on the old one once you have the new one.",
                    secret.provider.display_name()
                )
            });
            self.emit(secret, RotationStage::Failed, &hint);
            return Err(RotationError::ManualActionRequired(hint));
        }

        // Refuse before minting anything: a new secret with nowhere to go is
        // a lost secret (and for Atomic providers, a lost account).
        if secret.consumers.is_empty() {
            self.emit(
                secret,
                RotationStage::Failed,
                "No destination for the new secret.",
            );
            return Err(RotationError::NoDestination(secret.label.clone()));
        }

        match connector.rotation_style() {
            RotationStyle::Overlap => self.rotate_overlap(connector, secret, delete_old_now).await,
            RotationStyle::AtomicRotate => self.rotate_atomic(connector, secret).await,
            RotationStyle::Ephemeral => self.rotate_ephemeral(connector, secret).await,
            RotationStyle::Manual => unreachable!(),
        }
    }

    /// Overlap: old key stays live until the new one is proven and delivered.
    ///
    /// Order is create → verify → update consumers → deactivate/delete old.
    /// Verifying first means no consumer is ever pointed at a key we might
    /// still destroy.
    async fn rotate_overlap(
        &self,
        connector: &Arc<dyn Connector>,
        secret: &Secret,
        delete_old_now: bool,
    ) -> Result<RotationOutcome, RotationError> {
        self.emit(secret, RotationStage::Creating, "Creating new credential…");
        let cred = connector.create(secret).await?;

        self.emit(
            secret,
            RotationStage::Verifying,
            "Verifying new credential…",
        );
        if let Err(e) = connector.verify(&cred).await {
            self.rollback(connector, secret, &cred, &e).await;
            return Err(e);
        }

        let mut outcome = self.deliver(secret, &cred).await;
        if outcome.updated_consumers.is_empty() {
            // Nothing references the new key yet, so undo cleanly.
            let e = RotationError::ConsumerUpdate(
                outcome
                    .failed_consumers
                    .iter()
                    .map(|(c, e)| format!("{}: {e}", c.describe()))
                    .collect::<Vec<_>>()
                    .join("; "),
            );
            self.rollback(connector, secret, &cred, &e).await;
            return Err(e);
        }

        outcome.old_key = OldKeyState::StillActive;
        if !outcome.failed_consumers.is_empty() {
            // Some consumers have the new key, some still have the old one.
            // Both keys work, so nothing is broken — leave the old one alone.
            outcome.problems.push(format!(
                "Old key {} left active because {} consumer(s) still need the new key. \
                 Fix them, then run `keyrotator retire`.",
                secret.external_id,
                outcome.failed_consumers.len()
            ));
            self.emit(
                secret,
                RotationStage::Failed,
                "Partially rotated; old key kept.",
            );
            return Ok(outcome);
        }

        if connector.supports_deactivate() {
            self.emit(
                secret,
                RotationStage::DeactivatingOld,
                "Deactivating old credential…",
            );
            match connector.deactivate_old(&secret.external_id).await {
                Ok(()) => outcome.old_key = OldKeyState::Deactivated,
                Err(e) => {
                    outcome
                        .problems
                        .push(format!("Couldn't deactivate old key: {e}"));
                    self.emit(secret, RotationStage::Failed, "Old key still active.");
                    return Ok(outcome);
                }
            }
        }

        if delete_old_now {
            self.emit(
                secret,
                RotationStage::DeletingOld,
                "Deleting old credential…",
            );
            match connector.delete_old(&secret.external_id).await {
                Ok(()) => outcome.old_key = OldKeyState::Deleted,
                Err(e) => outcome
                    .problems
                    .push(format!("Couldn't delete old key: {e}")),
            }
        }

        self.finish(secret, &outcome);
        Ok(outcome)
    }

    /// Atomic: the provider mints the new secret and revokes the old one in one
    /// call. There's no going back, so every consumer is attempted, and if all
    /// of them fail the secret is written to a rescue file rather than lost.
    async fn rotate_atomic(
        &self,
        connector: &Arc<dyn Connector>,
        secret: &Secret,
    ) -> Result<RotationOutcome, RotationError> {
        self.emit(
            secret,
            RotationStage::Creating,
            "Rotating (provider revokes old token immediately)…",
        );
        let cred = connector.create(secret).await?;

        let mut outcome = self.deliver(secret, &cred).await;
        outcome.old_key = OldKeyState::Revoked;
        self.rescue_if_undelivered(secret, &cred, &mut outcome);

        self.emit(secret, RotationStage::Verifying, "Verifying new token…");
        if let Err(e) = connector.verify(&cred).await {
            outcome.problems.push(format!(
                "New token failed verification and the old one is already revoked: {e}. \
                 Re-run rotate for {}.",
                secret.label
            ));
        }

        self.finish(secret, &outcome);
        Ok(outcome)
    }

    /// Ephemeral: mint a fresh short-lived token, push it to consumers, verify.
    /// Nothing to revoke — the previous token expires on its own.
    async fn rotate_ephemeral(
        &self,
        connector: &Arc<dyn Connector>,
        secret: &Secret,
    ) -> Result<RotationOutcome, RotationError> {
        self.emit(
            secret,
            RotationStage::Creating,
            "Minting short-lived token…",
        );
        let cred = connector.create(secret).await?;

        self.emit(secret, RotationStage::Verifying, "Verifying new token…");
        connector.verify(&cred).await?;

        let mut outcome = self.deliver(secret, &cred).await;
        outcome.old_key = OldKeyState::NotApplicable;
        if outcome.updated_consumers.is_empty() {
            // The token simply expires; nothing changed for anyone.
            return Err(RotationError::ConsumerUpdate(
                "no consumer accepted the new token".into(),
            ));
        }
        self.finish(secret, &outcome);
        Ok(outcome)
    }

    /// Push the credential to every consumer, collecting successes and
    /// failures instead of stopping at the first error.
    async fn deliver(&self, secret: &Secret, cred: &NewCredential) -> RotationOutcome {
        self.emit(
            secret,
            RotationStage::UpdatingConsumers,
            &format!("Updating {} consumer(s)…", secret.consumers.len()),
        );
        let mut outcome = RotationOutcome {
            new_external_id: cred.external_id.clone(),
            old_key: OldKeyState::StillActive,
            updated_consumers: Vec::new(),
            failed_consumers: Vec::new(),
            revealed_secret: None,
            rescue_file: None,
            problems: Vec::new(),
        };
        for consumer in &secret.consumers {
            match self.updater.update(consumer, cred).await {
                Ok(()) => {
                    if *consumer == Consumer::Reveal {
                        outcome.revealed_secret = Some(cred.secret_value.clone());
                    }
                    outcome.updated_consumers.push(consumer.clone());
                }
                Err(e) => {
                    self.emit(
                        secret,
                        RotationStage::UpdatingConsumers,
                        &format!("Failed to update {}: {e}", consumer.describe()),
                    );
                    outcome
                        .failed_consumers
                        .push((consumer.clone(), e.to_string()));
                }
            }
        }
        outcome
    }

    fn rescue_if_undelivered(
        &self,
        secret: &Secret,
        cred: &NewCredential,
        outcome: &mut RotationOutcome,
    ) {
        if !outcome.updated_consumers.is_empty() {
            return;
        }
        let safe_id: String = cred
            .external_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let path = self.rescue_dir.join(format!(
            "keyrotator-rescue-{:?}-{safe_id}.secret",
            secret.provider
        ));
        match write_private(&path, format!("{}\n", cred.secret_value).as_bytes()) {
            Ok(()) => {
                outcome.problems.push(format!(
                    "Every consumer failed, so the new secret was saved to {} (owner-only). \
                     Move it somewhere safe and delete the file.",
                    path.display()
                ));
                outcome.rescue_file = Some(path);
            }
            Err(e) => outcome.problems.push(format!(
                "Every consumer failed and the rescue file couldn't be written ({e}). \
                 The new secret is lost; re-run rotate."
            )),
        }
    }

    async fn rollback(
        &self,
        connector: &Arc<dyn Connector>,
        secret: &Secret,
        cred: &NewCredential,
        cause: &RotationError,
    ) {
        self.emit(
            secret,
            RotationStage::RolledBack,
            &format!("Rolling back: {cause}"),
        );
        // Destroy the new key; the old one was never touched.
        let _ = connector.delete_old(&cred.external_id).await;
    }

    fn finish(&self, secret: &Secret, outcome: &RotationOutcome) {
        if outcome.is_clean() {
            self.emit(secret, RotationStage::Done, "Rotated successfully.");
        } else {
            self.emit(
                secret,
                RotationStage::Failed,
                "Rotated, but needs attention.",
            );
        }
    }

    /// Permanently retire a key you no longer use: deactivate it where the
    /// provider supports that, and delete it when `delete` is set (or when
    /// deleting is the provider's only way to revoke).
    pub async fn retire(
        &self,
        provider: ProviderKind,
        external_id: &str,
        delete: bool,
    ) -> Result<OldKeyState, RotationError> {
        let connector = self.connector(provider)?;
        match connector.rotation_style() {
            RotationStyle::AtomicRotate => {
                return Err(RotationError::NotImplemented(format!(
                    "{} revokes the old token during rotate; there is nothing to retire",
                    provider.display_name()
                )))
            }
            RotationStyle::Ephemeral => {
                return Err(RotationError::NotImplemented(format!(
                    "{} tokens expire on their own",
                    provider.display_name()
                )))
            }
            RotationStyle::Overlap | RotationStyle::Manual => {}
        }
        let mut state = OldKeyState::StillActive;
        if connector.supports_deactivate() {
            connector.deactivate_old(external_id).await?;
            state = OldKeyState::Deactivated;
        }
        if delete || !connector.supports_deactivate() {
            connector.delete_old(external_id).await?;
            state = OldKeyState::Deleted;
        }
        Ok(state)
    }

    /// Rotate many secrets concurrently. Returns a map of secret id → result.
    pub async fn rotate_all(
        &self,
        secrets: &[Secret],
        delete_old_now: bool,
    ) -> HashMap<uuid::Uuid, Result<RotationOutcome, RotationError>> {
        let jobs = secrets
            .iter()
            .map(|s| async move { (s.id, self.rotate(s, delete_old_now).await) });
        futures::future::join_all(jobs).await.into_iter().collect()
    }
}
