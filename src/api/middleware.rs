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
/// Optional dedicated header carrying privileged operator credentials (`OPERATOR_API_KEY`).
pub const OPERATOR_API_KEY_HEADER: &str = "x-operator-key";

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

    let valid_merchant = constant_time_key_match(presented, &state.config.api_secret_key);
    let valid_operator = state
        .config
        .operator_api_key
        .as_deref()
        .is_some_and(|op| constant_time_key_match(presented, op));

    if !valid_merchant && !valid_operator {
        return Err(GatewayError::Unauthorized("invalid X-API-Key".to_string()));
    }

    Ok(next.run(request).await)
}

/// Verifies operator authorization for sensitive sweep/recovery routes (`OPERATOR_API_KEY`).
///
/// When `OPERATOR_API_KEY` is configured, accepts `X-Operator-Key` or `X-API-Key` ONLY when
/// it matches `OPERATOR_API_KEY` in constant time (returning `403 Forbidden` if a valid merchant
/// `API_SECRET_KEY` is presented, or `401 Unauthorized` if missing/unknown). When
/// `OPERATOR_API_KEY` is unset, falls back cleanly to `API_SECRET_KEY` for single-tenant mode.
///
/// # Errors
/// Returns [`GatewayError::Unauthorized`] (`401`) or [`GatewayError::Forbidden`] (`403`).
pub async fn require_operator_key(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, GatewayError> {
    let presented = request
        .headers()
        .get(OPERATOR_API_KEY_HEADER)
        .or_else(|| request.headers().get(API_KEY_HEADER))
        .ok_or_else(|| {
            GatewayError::Unauthorized("missing X-API-Key / X-Operator-Key header".to_string())
        })?
        .to_str()
        .map_err(|_| {
            GatewayError::Unauthorized("invalid operator key header encoding".to_string())
        })?;

    if let Some(ref op_key) = state.config.operator_api_key {
        if constant_time_key_match(presented, op_key) {
            return Ok(next.run(request).await);
        }
        if constant_time_key_match(presented, &state.config.api_secret_key) {
            return Err(GatewayError::Forbidden(
                "operator privileges (OPERATOR_API_KEY) required for this endpoint".to_string(),
            ));
        }
        return Err(GatewayError::Unauthorized(
            "invalid operator API key".to_string(),
        ));
    }

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
