//! JWT issuing and validation (RS256).
//!
//! Access tokens are short-lived OIDC-style JWTs carrying subject, audience,
//! scopes and roles. Validation is done with the public key only, so resource
//! servers never need a shared secret.

use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::keys::SigningKey;

/// Standard + custom claims for an Infinity ID access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — the user (or client) id.
    pub sub: String,
    /// Issuer — the Infinity ID base URL.
    pub iss: String,
    /// Audience — the intended resource server / client.
    pub aud: String,
    /// Expiry (unix seconds).
    pub exp: i64,
    /// Issued-at (unix seconds).
    pub iat: i64,
    /// Not-before (unix seconds).
    pub nbf: i64,
    /// Space-delimited OAuth2 scopes.
    #[serde(default)]
    pub scope: String,
    /// Assigned RBAC roles.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Preferred username / email for convenience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// Token type marker (`access` or `id`).
    #[serde(default)]
    pub typ: String,
}

/// Sign a set of claims into a compact JWT using the active signing key.
pub fn issue(key: &SigningKey, claims: &Claims) -> Result<String> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    let enc = EncodingKey::from_rsa_pem(key.private_pem.as_bytes())
        .map_err(|e| CoreError::Crypto(format!("encoding key: {e}")))?;
    encode(&header, claims, &enc).map_err(|e| CoreError::Crypto(format!("sign token: {e}")))
}

/// Inspect and strictly validate the JWT header before signature verification.
///
/// Rejects any non-RS256 algorithm (no `none`, no `HS256` key-confusion),
/// embedded key headers (`jku`, `jwk`, `x5u`, `x5c`), or unsupported `crit`.
pub fn inspect_header(token: &str) -> Result<Header> {
    let header = decode_header(token).map_err(|e| CoreError::Token(e.to_string()))?;
    if header.alg != Algorithm::RS256 {
        return Err(CoreError::Token("unsupported token algorithm".into()));
    }
    if header.jku.is_some() || header.jwk.is_some() || header.x5u.is_some() || header.x5c.is_some()
    {
        return Err(CoreError::Token("disallowed JWT header parameter".into()));
    }
    Ok(header)
}

/// Validate a JWT against RSA public components `(n, e)` (base64url) and issuer.
pub fn validate_with_components(
    token: &str,
    n_b64: &str,
    e_b64: &str,
    issuer: &str,
    audience: Option<&str>,
) -> Result<Claims> {
    inspect_header(token)?;
    let dec = DecodingKey::from_rsa_components(n_b64, e_b64)
        .map_err(|e| CoreError::Token(format!("decoding key: {e}")))?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.algorithms = vec![Algorithm::RS256];
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 5;
    validation.set_issuer(&[issuer]);
    validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud", "sub"]);
    match audience {
        Some(a) => validation.set_audience(&[a]),
        None => validation.validate_aud = false,
    }
    let data =
        decode::<Claims>(token, &dec, &validation).map_err(|e| CoreError::Token(e.to_string()))?;
    if data.claims.sub.trim().is_empty() || data.claims.aud.trim().is_empty() {
        return Err(CoreError::Token("empty subject or audience".into()));
    }
    if data.claims.exp <= data.claims.nbf {
        return Err(CoreError::Token("invalid token validity window".into()));
    }
    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyRing;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    fn now_ts() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn sample_claims(now: i64) -> Claims {
        Claims {
            sub: "user-1".into(),
            iss: "https://id.example.com".into(),
            aud: "api.example.com".into(),
            exp: now + 300,
            iat: now,
            nbf: now,
            scope: "openid".into(),
            roles: vec!["user".into()],
            preferred_username: Some("alice".into()),
            typ: "access".into(),
        }
    }

    #[test]
    fn enforces_alg_iss_aud_exp_and_nbf() {
        let dir =
            std::env::temp_dir().join(format!("infinity-token-test-{}", uuid::Uuid::new_v4()));
        let key_path = dir.join("signing_key.pem");
        let ring = KeyRing::load_or_generate(&key_path, 3600).unwrap();
        let now = now_ts();
        let claims = sample_claims(now);
        let tok = issue(&ring.active, &claims).unwrap();

        let verified = validate_with_components(
            &tok,
            &ring.active.jwk.n,
            &ring.active.jwk.e,
            "https://id.example.com",
            Some("api.example.com"),
        )
        .unwrap();
        assert_eq!(verified.sub, "user-1");

        // Wrong issuer rejected
        assert!(validate_with_components(
            &tok,
            &ring.active.jwk.n,
            &ring.active.jwk.e,
            "https://evil.example.com",
            Some("api.example.com"),
        )
        .is_err());

        // Wrong audience rejected
        assert!(validate_with_components(
            &tok,
            &ring.active.jwk.n,
            &ring.active.jwk.e,
            "https://id.example.com",
            Some("other-api.example.com"),
        )
        .is_err());

        // Future nbf rejected
        let mut future_nbf = claims.clone();
        future_nbf.nbf = now + 120;
        future_nbf.exp = now + 400;
        let future_tok = issue(&ring.active, &future_nbf).unwrap();
        assert!(validate_with_components(
            &future_tok,
            &ring.active.jwk.n,
            &ring.active.jwk.e,
            "https://id.example.com",
            Some("api.example.com"),
        )
        .is_err());

        // Expired exp rejected
        let mut expired = claims.clone();
        expired.nbf = now - 600;
        expired.iat = now - 600;
        expired.exp = now - 120;
        let expired_tok = issue(&ring.active, &expired).unwrap();
        assert!(validate_with_components(
            &expired_tok,
            &ring.active.jwk.n,
            &ring.active.jwk.e,
            "https://id.example.com",
            Some("api.example.com"),
        )
        .is_err());

        // alg=none unsigned token rejected
        let none_hdr = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let none_tok = format!("{none_hdr}.{payload}.");
        assert!(validate_with_components(
            &none_tok,
            &ring.active.jwk.n,
            &ring.active.jwk.e,
            "https://id.example.com",
            Some("api.example.com"),
        )
        .is_err());

        // Disallowed jku header rejected
        let mut jku_hdr = Header::new(Algorithm::RS256);
        jku_hdr.kid = Some(ring.active.kid.clone());
        jku_hdr.jku = Some("https://evil.example.com/jwks.json".into());
        let enc = EncodingKey::from_rsa_pem(ring.active.private_pem.as_bytes()).unwrap();
        let jku_tok = encode(&jku_hdr, &claims, &enc).unwrap();
        assert!(validate_with_components(
            &jku_tok,
            &ring.active.jwk.n,
            &ring.active.jwk.e,
            "https://id.example.com",
            Some("api.example.com"),
        )
        .is_err());

        std::fs::remove_dir_all(dir).ok();
    }
}
