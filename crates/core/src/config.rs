//! `rekey.toml`: where each key's consumers live.
//!
//! ```toml
//! [[keys]]
//! provider = "gitlab"
//! name = "ci-deploy"          # match by name, id, and/or principal
//! consumers = [
//!   { type = "dot_env_file", path = ".env", variable = "GITLAB_TOKEN" },
//!   { type = "github_actions_secret", repo = "me/app", secret_name = "GITLAB_TOKEN" },
//! ]
//! ```
//!
//! Match on `name` or `principal` for providers that issue a new id on every
//! rotation (AWS, GitLab, Datadog, …) so the entry keeps matching afterwards.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer};

use crate::models::{Consumer, ProviderKind, Secret};

pub const FILE_NAME: &str = "rekey.toml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub keys: Vec<KeyConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    #[serde(deserialize_with = "provider_from_str")]
    pub provider: ProviderKind,
    pub id: Option<String>,
    pub name: Option<String>,
    pub principal: Option<String>,
    #[serde(default)]
    pub consumers: Vec<Consumer>,
}

fn provider_from_str<'de, D: Deserializer<'de>>(d: D) -> Result<ProviderKind, D::Error> {
    let s = String::deserialize(d)?;
    s.parse().map_err(serde::de::Error::custom)
}

impl KeyConfig {
    fn matches(&self, secret: &Secret) -> bool {
        self.provider == secret.provider
            && self.id.as_ref().is_none_or(|v| *v == secret.external_id)
            && self.name.as_ref().is_none_or(|v| *v == secret.label)
            && self
                .principal
                .as_ref()
                .is_none_or(|v| *v == secret.principal)
    }
}

impl Config {
    pub fn parse(text: &str, base_dir: &Path) -> Result<Self, String> {
        let mut cfg: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        for (i, key) in cfg.keys.iter_mut().enumerate() {
            if key.id.is_none() && key.name.is_none() && key.principal.is_none() {
                return Err(format!(
                    "keys[{i}] ({}) needs at least one of `id`, `name`, or `principal`",
                    key.provider.display_name()
                ));
            }
            // Relative paths are relative to the config file, not the cwd.
            for c in key.consumers.iter_mut() {
                if let Consumer::DotEnvFile { path, .. } | Consumer::File { path } = c {
                    if Path::new(path.as_str()).is_relative() {
                        *path = base_dir.join(&*path).to_string_lossy().into_owned();
                    }
                }
            }
        }
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        Self::parse(&text, base).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// `explicit` if given; otherwise `./rekey.toml`, then
    /// `$XDG_CONFIG_HOME/rekey/config.toml` (or `~/.config/...`).
    pub fn discover(explicit: Option<&Path>) -> Result<Option<(PathBuf, Self)>, String> {
        if let Some(p) = explicit {
            return Self::load(p).map(|c| Some((p.to_path_buf(), c)));
        }
        let mut candidates = vec![PathBuf::from(FILE_NAME)];
        let xdg = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
        if let Some(dir) = xdg {
            candidates.push(dir.join("rekey").join("config.toml"));
        }
        for p in candidates {
            if p.is_file() {
                return Self::load(&p).map(|c| Some((p, c)));
            }
        }
        Ok(None)
    }

    /// Consumers configured for this key, from every matching entry.
    pub fn consumers_for(&self, secret: &Secret) -> Vec<Consumer> {
        self.keys
            .iter()
            .filter(|k| k.matches(secret))
            .flat_map(|k| k.consumers.iter().cloned())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[[keys]]
provider = "gitlab"
name = "ci-deploy"
consumers = [
  { type = "dot_env_file", path = ".env", variable = "GITLAB_TOKEN" },
  { type = "github_actions_secret", repo = "me/app", secret_name = "GITLAB_TOKEN" },
]

[[keys]]
provider = "aws"
principal = "ci-user"
consumers = [{ type = "aws_ssm_parameter", name = "/ci/aws", region = "us-east-1" }]
"#;

    #[test]
    fn matches_by_name_and_resolves_relative_paths() {
        let cfg = Config::parse(SAMPLE, Path::new("/proj")).unwrap();
        let s = Secret::new(ProviderKind::Gitlab, "4822", "ci-deploy", "4822");
        let c = cfg.consumers_for(&s);
        assert_eq!(c.len(), 2);
        assert_eq!(
            c[0],
            Consumer::DotEnvFile {
                // Platform separator: `/proj/.env` here, `/proj\.env` on Windows.
                path: Path::new("/proj").join(".env").to_string_lossy().into(),
                variable: "GITLAB_TOKEN".into(),
                id_variable: None,
            }
        );
    }

    #[test]
    fn matches_by_principal_across_new_key_ids() {
        let cfg = Config::parse(SAMPLE, Path::new(".")).unwrap();
        let s = Secret::new(
            ProviderKind::Aws,
            "AKIANEW",
            "IAM key for ci-user",
            "ci-user",
        );
        assert_eq!(cfg.consumers_for(&s).len(), 1);
        let other = Secret::new(ProviderKind::Aws, "AKIAX", "IAM key for bob", "bob");
        assert!(cfg.consumers_for(&other).is_empty());
    }

    #[test]
    fn rejects_entries_without_a_selector() {
        let err = Config::parse("[[keys]]\nprovider = \"aws\"\n", Path::new(".")).unwrap_err();
        assert!(err.contains("at least one"), "{err}");
    }

    #[test]
    fn reveal_cannot_come_from_config() {
        let text =
            "[[keys]]\nprovider = \"aws\"\nid = \"x\"\nconsumers = [{ type = \"reveal\" }]\n";
        assert!(Config::parse(text, Path::new(".")).is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let text = "[[keys]]\nprovider = \"aws\"\nid = \"x\"\nconsumer = []\n";
        assert!(Config::parse(text, Path::new(".")).is_err());
    }
}
