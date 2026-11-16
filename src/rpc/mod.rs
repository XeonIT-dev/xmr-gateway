//! JSON-RPC 2.0 client and DTOs for communicating with `monero-wallet-rpc`.
//!
//! Supports unauthenticated local IPC/loopback connections as well as RFC 2617/7616
//! HTTP Digest Authentication (Monero's default `--rpc-login` mechanism) and Basic
//! Authentication.

pub mod client;
pub mod types;
