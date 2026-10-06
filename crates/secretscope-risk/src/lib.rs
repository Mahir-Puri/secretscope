//! SecretScope risk scoring.
//!
//! Turns a blast radius into an explainable severity. The rules are fixed and
//! documented in `score.rs`, and every point that is added also produces a
//! reason so the result can be read and argued with rather than trusted blindly.

mod score;
mod severity;

pub use score::{assess, RiskAssessment};
pub use severity::Severity;
