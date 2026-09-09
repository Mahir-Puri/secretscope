//! SecretScope local IAM model.
//!
//! Loads synthetic AWS IAM fixtures and answers permission questions with
//! explicit-deny-wins semantics. This is not a reproduction of AWS
//! authorization; it is a small model that is enough to demonstrate meaningful
//! blast-radius analysis. Everything is deterministic and runs offline.

mod eval;
mod model;
mod parse;
mod wildcard;

pub use eval::{evaluate, Decision, ACTION_VOCABULARY};
pub use model::{
    Account, CredentialMapping, Effect, Policy, PrincipalRef, Resource, Role, Statement, User,
};
pub use parse::{load_account, IamError};
pub use wildcard::glob_match;
