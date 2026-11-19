//! infinity-core — security primitives and domain model for Infinity ID.
//!
//! Everything security-critical lives here: password hashing (Argon2id),
//! asymmetric JWT signing (RS256 + JWKS), TOTP MFA, and the RBAC model.

pub mod error;
pub mod keys;
pub mod mfa;
pub mod model;
pub mod password;
pub mod rbac;
pub mod token;

pub use error::CoreError;
