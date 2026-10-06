//! Optional configuration file support.
//!
//! Every field is optional and has a sensible default. Command line flags
//! override configuration values; see `run.rs` for the merge. The format is
//! small on purpose. It is not a general policy language.

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub severity_threshold: Option<String>,
    pub scan_history: Option<bool>,
    pub entropy_threshold: Option<f64>,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
}

impl FileConfig {
    /// Load configuration from a specific path.
    pub fn load(path: &Path) -> anyhow::Result<FileConfig> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config {}: {e}", path.display()))?;
        let cfg: FileConfig = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("failed to parse config {}: {e}", path.display()))?;
        Ok(cfg)
    }

    /// Load `./.secretscope.toml` under `root` if it exists, else defaults.
    pub fn discover(root: &Path) -> anyhow::Result<FileConfig> {
        let candidate = root.join(".secretscope.toml");
        if candidate.is_file() {
            FileConfig::load(&candidate)
        } else {
            Ok(FileConfig::default())
        }
    }
}
