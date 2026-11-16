//! Constant-time `X-API-Key` authentication middleware for protected `/api/v1/*` endpoints.
//!
//! # Timing Side-Channel Defense
//! `subtle::ConstantTimeEq` returns `Choice(0)` early if slice lengths differ, which would leak
//! the length of `API_SECRET_KEY` over high-sample network timing attacks. To eliminate length
//! leakage completely, both the presented `X-API-Key` header and the expected `API_SECRET_KEY`
//! are hashed with SHA-256 into fixed 32-byte digests prior to constant-time comparison.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{api::AppState, error::GatewayError};

/// Header name carrying the merchant API authentication secret.
pub const API_KEY_HEADER: &str = "x-api-key";

/// Verifies `X-API-Key` against `config.api_secret_key` in constant time.
///
/// # Errors
/// Returns [`GatewayError::Unauthorized`] (`401`) if the header is missing, non-ASCII/UTF-8,
/// or fails digest equality.
pub async fn require_api_key(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, GatewayError> {
    let presented = request
        .headers()
        .get(API_KEY_HEADER)
        .ok_or_else(|| GatewayError::Unauthorized("missing X-API-Key header".to_string()))?
        .to_str()
        .map_err(|_| GatewayError::Unauthorized("invalid X-API-Key header encoding".to_string()))?;

    if !constant_time_key_match(presented, &state.config.api_secret_key) {
        return Err(GatewayError::Unauthorized("invalid X-API-Key".to_string()));
    }

    Ok(next.run(request).await)
}

/// Compares two secret strings in constant time without leaking length via SHA-256 pre-hashing.
#[must_use]
pub fn constant_time_key_match(presented: &str, expected: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    let presented_digest = Sha256::digest(presented.as_bytes());
    let expected_digest = Sha256::digest(expected.as_bytes());
    bool::from(presented_digest.ct_eq(&expected_digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_comparison_handles_exact_mismatch_and_length_differences() {
        let expected = "super-long-secret-api-key-0123456789abcdef";
        assert!(constant_time_key_match(expected, expected));
        assert!(!constant_time_key_match("short", expected));
        assert!(!constant_time_key_match("", expected));
        assert!(!constant_time_key_match(
            "super-long-secret-api-key-0123456789abcdeg",
            expected
        ));
        assert!(!constant_time_key_match("anything", ""));
    }
}
