//! Loading an account from a directory of JSON fixtures.
//!
//! The directory is expected to contain some of: `users.json`, `roles.json`,
//! `policies.json`, `resources.json`, `credentials.json`. Each file is a JSON
//! array. Missing files are treated as empty, which keeps small fixtures tidy.
//! A file that exists but is malformed is a hard error, because silently
//! ignoring a broken policy could hide real permissions.

use crate::model::{Account, CredentialMapping, Policy, Resource, Role, User};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum IamError {
    #[error("IAM fixture directory not found: {0}")]
    DirNotFound(PathBuf),
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
}

fn load_array<T: serde::de::DeserializeOwned>(dir: &Path, file: &str) -> Result<Vec<T>, IamError> {
    let path = dir.join(file);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path).map_err(|source| IamError::Io {
        path: path.clone(),
        source,
    })?;
    serde_json::from_str(&text).map_err(|source| IamError::Parse { path, source })
}

/// Load an [`Account`] from `dir`.
pub fn load_account(dir: &Path) -> Result<Account, IamError> {
    if !dir.is_dir() {
        return Err(IamError::DirNotFound(dir.to_path_buf()));
    }
    let users: Vec<User> = load_array(dir, "users.json")?;
    let roles: Vec<Role> = load_array(dir, "roles.json")?;
    let policies: Vec<Policy> = load_array(dir, "policies.json")?;
    let resources: Vec<Resource> = load_array(dir, "resources.json")?;
    let credentials: Vec<CredentialMapping> = load_array(dir, "credentials.json")?;

    Ok(Account {
        users,
        roles,
        policies,
        resources,
        credentials,
    })
}
