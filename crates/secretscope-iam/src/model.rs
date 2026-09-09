//! Data types for the local IAM model.
//!
//! This is a deliberately small subset of AWS IAM: users, roles, managed
//! policies referenced by name, allow and deny statements, actions, resources,
//! and `sts:AssumeRole`. It does not model conditions, permission boundaries,
//! service control policies, session policies, or cross-account trust. See the
//! README for the full list of what is intentionally left out.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

/// A single permission statement inside a policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub effect: Effect,
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub resources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    #[serde(default)]
    pub statements: Vec<Statement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    #[serde(default)]
    pub policies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub arn: String,
    #[serde(default)]
    pub policies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    pub arn: String,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub environment: String,
    #[serde(default)]
    pub sensitive: bool,
}

impl Resource {
    pub fn is_production(&self) -> bool {
        self.environment.eq_ignore_ascii_case("production")
    }
}

/// Maps a detected credential's fingerprint to the principal it belongs to.
/// The raw credential is never stored here, only its SHA-256 fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMapping {
    pub fingerprint: String,
    pub principal: String,
}

/// A borrowed reference to whichever principal owns a set of policies.
#[derive(Debug, Clone, Copy)]
pub enum PrincipalRef<'a> {
    User(&'a User),
    Role(&'a Role),
}

impl<'a> PrincipalRef<'a> {
    pub fn name(&self) -> &'a str {
        match self {
            PrincipalRef::User(u) => &u.name,
            PrincipalRef::Role(r) => &r.name,
        }
    }

    pub fn policy_names(&self) -> &'a [String] {
        match self {
            PrincipalRef::User(u) => &u.policies,
            PrincipalRef::Role(r) => &r.policies,
        }
    }

    pub fn is_role(&self) -> bool {
        matches!(self, PrincipalRef::Role(_))
    }
}

/// A fully loaded synthetic account.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Account {
    #[serde(default)]
    pub users: Vec<User>,
    #[serde(default)]
    pub roles: Vec<Role>,
    #[serde(default)]
    pub policies: Vec<Policy>,
    #[serde(default)]
    pub resources: Vec<Resource>,
    #[serde(default)]
    pub credentials: Vec<CredentialMapping>,
}

impl Account {
    pub fn user_by_name(&self, name: &str) -> Option<&User> {
        self.users.iter().find(|u| u.name == name)
    }

    pub fn role_by_name(&self, name: &str) -> Option<&Role> {
        self.roles.iter().find(|r| r.name == name)
    }

    pub fn policy_by_name(&self, name: &str) -> Option<&Policy> {
        self.policies.iter().find(|p| p.name == name)
    }

    /// A user or a role, whichever carries this name.
    pub fn principal_by_name(&self, name: &str) -> Option<PrincipalRef<'_>> {
        if let Some(u) = self.user_by_name(name) {
            return Some(PrincipalRef::User(u));
        }
        self.role_by_name(name).map(PrincipalRef::Role)
    }

    /// Resolve a principal's policy names into policy references, skipping any
    /// name that does not resolve. A missing policy is not fatal; it simply
    /// grants nothing.
    pub fn resolve_policies(&self, names: &[String]) -> Vec<&Policy> {
        names
            .iter()
            .filter_map(|n| self.policy_by_name(n))
            .collect()
    }

    /// Find the role whose ARN is matched by a resource pattern from an
    /// `sts:AssumeRole` statement.
    pub fn role_for_resource(&self, resource_pattern: &str) -> Option<&Role> {
        self.roles
            .iter()
            .find(|r| crate::wildcard::glob_match(resource_pattern, &r.arn))
    }

    /// Look up which principal a credential fingerprint belongs to.
    pub fn principal_for_fingerprint(&self, fingerprint: &str) -> Option<&str> {
        self.credentials
            .iter()
            .find(|c| c.fingerprint == fingerprint)
            .map(|c| c.principal.as_str())
    }
}
