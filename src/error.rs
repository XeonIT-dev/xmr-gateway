//! Unified error types and HTTP error mapping for `xmr-gateway`.
//!
//! All fallible operations across configuration, domain validation, SQLite persistence,
//! `monero-wallet-rpc` communication, QR code generation, and webhook delivery map into
//! [`GatewayError`]. At the HTTP boundary, errors are serialized into a stable JSON
//! envelope without leaking internal database queries, stack traces, or secret material.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

/// Domain-level validation, arithmetic, and state-transition errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// Monetary arithmetic overflowed or exceeded SQLite signed 64-bit bounds.
    #[error("piconero arithmetic overflow: {0}")]
    AmountOverflow(String),

    /// Monetary arithmetic underflowed below zero.
    #[error("piconero arithmetic underflow: {0}")]
    AmountUnderflow(String),

    /// An XMR decimal string could not be parsed without ambiguity or precision loss.
    #[error("invalid XMR amount string: {0}")]
    InvalidAmountFormat(String),

    /// An invoice field violated domain invariants (e.g., empty order_id or zero amount).
    #[error("invalid domain input: {0}")]
    Validation(String),

    /// An invoice state transition violated the deterministic payment state machine.
    #[error("invalid invoice state transition from {from} to {to}: {reason}")]
    InvalidStateTransition {
        /// Source status.
        from: String,
        /// Attempted target status.
        to: String,
        /// Explanation of the violated invariant.
        reason: String,
    },
}

/// Top-level application error enum used throughout the gateway.
#[derive(Debug, Error)]
pub enum GatewayError {
    /// Startup configuration is missing or fails security invariants.
    #[error("configuration error: {0}")]
    Config(String),

    /// Client supplied invalid API input.
    #[error("validation error: {0}")]
    Validation(String),

    /// Caller failed API key authentication.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Caller authenticated with merchant key but lacks operator privileges (`OPERATOR_API_KEY`).
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Upstream Monero RPC dependency is unavailable or failed a fail-closed safety check.
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Requested resource does not exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// Request conflicts with current resource state (e.g., duplicate order_id or locked funds).
    #[error("conflict: {0}")]
    Conflict(String),

    /// Domain invariant violation.
    #[error(transparent)]
    Domain(#[from] DomainError),

    /// SQLite persistence or transaction failure.
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Embedded SQLx migration failure on startup.
    #[error("database migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    /// JSON-RPC protocol error returned explicitly by `monero-wallet-rpc`.
    #[error("monero-wallet-rpc error (code {code:?}): {message}")]
    Rpc {
        /// JSON-RPC 2.0 error code returned by Monero wallet RPC.
        code: Option<i64>,
        /// Human-readable RPC error message.
        message: String,
    },

    /// Transport, authentication, or deserialization failure talking to `monero-wallet-rpc`.
    #[error("monero-wallet-rpc transport error: {0}")]
    RpcTransport(String),

    /// QR code matrix generation or PNG encoding failed.
    #[error("QR generation error: {0}")]
    QrGeneration(String),

    /// Outbound webhook signing or dispatch failed.
    #[error("webhook error: {0}")]
    Webhook(String),

    /// Unexpected internal invariant violation.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Canonical JSON error response body returned by the Axum API.
#[derive(Debug, Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorDetail<'a>,
}

/// Structured inner error payload inside [`ErrorEnvelope`].
#[derive(Debug, Serialize)]
struct ErrorDetail<'a> {
    code: &'a str,
    message: &'a str,
}

impl IntoResponse for GatewayError {
    /// Maps [`GatewayError`] variants to deterministic HTTP status codes and JSON payloads.
    ///
    /// Internal SQLite, transport, and QR errors are logged server-side and masked behind
    /// generic external messages so infrastructure internals are never disclosed.
    fn into_response(self) -> Response {
        let (status, code, public_message): (StatusCode, &str, String) = match &self {
            Self::Validation(msg) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR", msg.clone()),
            Self::Domain(DomainError::Validation(msg))
            | Self::Domain(DomainError::InvalidAmountFormat(msg))
            | Self::Domain(DomainError::AmountOverflow(msg))
            | Self::Domain(DomainError::AmountUnderflow(msg)) => (
                StatusCode::BAD_REQUEST,
                "DOMAIN_VALIDATION_ERROR",
                msg.clone(),
            ),
            Self::Domain(DomainError::InvalidStateTransition { .. }) => (
                StatusCode::CONFLICT,
                "INVALID_STATE_TRANSITION",
                self.to_string(),
            ),
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", msg.clone()),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, "FORBIDDEN", msg.clone()),
            Self::ServiceUnavailable(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                msg.clone(),
            ),
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg.clone()),
            Self::Conflict(msg) => (StatusCode::CONFLICT, "CONFLICT", msg.clone()),
            Self::Rpc { message, .. } => {
                tracing::error!(error = %self, "monero-wallet-rpc returned JSON-RPC error");
                (
                    StatusCode::BAD_GATEWAY,
                    "MONERO_RPC_ERROR",
                    format!("monero-wallet-rpc error: {message}"),
                )
            }
            Self::RpcTransport(msg) => {
                tracing::error!(error = %msg, "monero-wallet-rpc transport failure");
                (
                    StatusCode::BAD_GATEWAY,
                    "MONERO_RPC_UNAVAILABLE",
                    "unable to reach monero-wallet-rpc".to_string(),
                )
            }
            Self::Database(db_err) => {
                if let sqlx::Error::Database(inner) = db_err
                    && inner.is_unique_violation()
                {
                    return (
                        StatusCode::CONFLICT,
                        Json(ErrorEnvelope {
                            error: ErrorDetail {
                                code: "DUPLICATE_RESOURCE",
                                message: "resource with unique identifier already exists",
                            },
                        }),
                    )
                        .into_response();
                }
                tracing::error!(error = %self, "database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DATABASE_ERROR",
                    "internal persistence error".to_string(),
                )
            }
            Self::Config(_)
            | Self::Migration(_)
            | Self::QrGeneration(_)
            | Self::Webhook(_)
            | Self::Internal(_) => {
                tracing::error!(error = %self, "internal gateway failure");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "internal server error".to_string(),
                )
            }
        };

        (
            status,
            Json(ErrorEnvelope {
                error: ErrorDetail {
                    code,
                    message: &public_message,
                },
            }),
        )
            .into_response()
    }
}

/// Convenience result alias for gateway operations.
pub type GatewayResult<T> = Result<T, GatewayError>;
