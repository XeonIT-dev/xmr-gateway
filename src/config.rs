//! Runtime configuration loading and security invariant validation.
//!
//! Configuration is sourced from environment variables (and optionally `.env` via `dotenvy`).
//! Sensitive fields (`api_secret_key`, `webhook_secret`, `monero_rpc_pass`) are redacted in
//! [`std::fmt::Debug`] so accidental debug formatting never leaks secrets into structured logs.

use std::{env, fmt, net::SocketAddr};

use url::Url;

use crate::error::{GatewayError, GatewayResult};

/// Monero Base58 alphabet used in standard, integrated, and subaddress strings.
const MONERO_BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Structured logging output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Structured JSON logs for production log collectors.
    Json,
    /// Human-readable ANSI-free/compact logs for local development.
    Pretty,
}

impl LogFormat {
    /// Parses `LOG_FORMAT` environment variable value (`json` or `pretty`).
    fn parse(raw: &str) -> GatewayResult<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "pretty" => Ok(Self::Pretty),
            other => Err(GatewayError::Config(format!(
                "invalid LOG_FORMAT '{other}': expected 'json' or 'pretty'"
            ))),
        }
    }
}

/// Complete, validated configuration for `xmr-gateway`.
///
/// # Security Invariants
/// - `api_secret_key` and `webhook_secret` must be non-empty.
/// - `required_confirmations` must be `>= 1` so `CONFIRMED` never aliases `MEMPOOL` (`0-conf`).
/// - When `enable_auto_sweep == true`, `cold_wallet_address` MUST be present and pass Monero
///   address structural validation (length, network prefix, Base58 alphabet).
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    /// Host IP/interface to bind the HTTP server on.
    pub host: String,
    /// TCP port to bind the HTTP server on.
    pub port: u16,
    /// Allowed CORS origins (`["*"]` permits any origin).
    pub cors_allowed_origins: Vec<String>,
    /// SQLite connection URL (e.g., `sqlite://data/xmr_gateway.db`).
    pub database_url: String,
    /// API secret key expected in `X-API-Key` header.
    pub api_secret_key: String,
    /// Shared secret for HMAC-SHA256 webhook body signatures (`X-Signature-256`).
    pub webhook_secret: String,
    /// Optional fallback webhook URL used when invoice creation omits `callback_url`.
    pub default_webhook_url: Option<String>,
    /// Full HTTP/HTTPS URL to `monero-wallet-rpc` JSON-RPC endpoint.
    pub monero_rpc_url: String,
    /// Optional RPC username for `--rpc-login` Digest/Basic authentication.
    pub monero_rpc_user: Option<String>,
    /// Optional RPC password for `--rpc-login` Digest/Basic authentication.
    pub monero_rpc_pass: Option<String>,
    /// Destination Monero address for automated and manual sweeps.
    pub cold_wallet_address: Option<String>,
    /// Custody mode flag: `false` = View-Only Zero-Trust, `true` = Hot Auto-Sweep.
    pub enable_auto_sweep: bool,
    /// Monero transaction priority (`0..=4`) passed to `sweep_all`.
    pub sweep_priority: u32,
    /// Minimum block confirmations required before transitioning an invoice to `CONFIRMED`.
    pub required_confirmations: u64,
    /// Default invoice expiration window in seconds.
    pub invoice_ttl_seconds: u64,
    /// Interval in seconds between background scanner polls against `monero-wallet-rpc`.
    pub scan_interval_seconds: u64,
    /// Interval in seconds between background webhook retry polls.
    pub webhook_poll_interval_seconds: u64,
    /// Tracing log output format.
    pub log_format: LogFormat,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("cors_allowed_origins", &self.cors_allowed_origins)
            .field("database_url", &self.database_url)
            .field("api_secret_key", &"[REDACTED]")
            .field("webhook_secret", &"[REDACTED]")
            .field("default_webhook_url", &self.default_webhook_url)
            .field("monero_rpc_url", &self.monero_rpc_url)
            .field("monero_rpc_user", &self.monero_rpc_user)
            .field(
                "monero_rpc_pass",
                &self.monero_rpc_pass.as_ref().map(|_| "[REDACTED]"),
            )
            .field("cold_wallet_address", &self.cold_wallet_address)
            .field("enable_auto_sweep", &self.enable_auto_sweep)
            .field("sweep_priority", &self.sweep_priority)
            .field("required_confirmations", &self.required_confirmations)
            .field("invoice_ttl_seconds", &self.invoice_ttl_seconds)
            .field("scan_interval_seconds", &self.scan_interval_seconds)
            .field(
                "webhook_poll_interval_seconds",
                &self.webhook_poll_interval_seconds,
            )
            .field("log_format", &self.log_format)
            .finish()
    }
}

impl Config {
    /// Loads configuration from process environment variables and validates all invariants.
    ///
    /// # Errors
    /// Returns [`GatewayError::Config`] if required secrets are missing, numeric values fail
    /// parsing, URLs are malformed, or `ENABLE_AUTO_SWEEP=true` lacks a valid `COLD_WALLET_ADDRESS`.
    pub fn from_env() -> GatewayResult<Self> {
        let host = env_or_default("HOST", "127.0.0.1");
        let port = parse_env_u16("PORT", 8080)?;
        let cors_raw = env_or_default("CORS_ALLOWED_ORIGINS", "");
        let cors_allowed_origins = cors_raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();

        let database_url = env_or_default("DATABASE_URL", "sqlite://data/xmr_gateway.db");
        let api_secret_key = require_non_empty_env("API_SECRET_KEY")?;
        let webhook_secret = require_non_empty_env("WEBHOOK_SECRET")?;
        let default_webhook_url = optional_non_empty_env("DEFAULT_WEBHOOK_URL");
        let monero_rpc_url = env_or_default("MONERO_RPC_URL", "http://127.0.0.1:18082/json_rpc");
        let monero_rpc_user = optional_non_empty_env("MONERO_RPC_USER");
        let monero_rpc_pass = optional_non_empty_env("MONERO_RPC_PASS");
        let cold_wallet_address = optional_non_empty_env("COLD_WALLET_ADDRESS");
        let enable_auto_sweep = parse_env_bool("ENABLE_AUTO_SWEEP", false)?;
        let sweep_priority = parse_env_u32("SWEEP_PRIORITY", 0)?;
        let required_confirmations = parse_env_u64("REQUIRED_CONFIRMATIONS", 2)?;
        let invoice_ttl_seconds = parse_env_u64("INVOICE_TTL_SECONDS", 3600)?;
        let scan_interval_seconds = parse_env_u64("SCAN_INTERVAL_SECONDS", 10)?;
        let webhook_poll_interval_seconds = parse_env_u64("WEBHOOK_POLL_INTERVAL_SECONDS", 5)?;
        let log_format = LogFormat::parse(&env_or_default("LOG_FORMAT", "json"))?;

        let config = Self {
            host,
            port,
            cors_allowed_origins,
            database_url,
            api_secret_key,
            webhook_secret,
            default_webhook_url,
            monero_rpc_url,
            monero_rpc_user,
            monero_rpc_pass,
            cold_wallet_address,
            enable_auto_sweep,
            sweep_priority,
            required_confirmations,
            invoice_ttl_seconds,
            scan_interval_seconds,
            webhook_poll_interval_seconds,
            log_format,
        };

        config.validate()?;
        Ok(config)
    }

    /// Validates all cross-field security and operational invariants.
    ///
    /// # Errors
    /// Returns [`GatewayError::Config`] on invalid socket bind address, weak/missing secrets,
    /// invalid RPC/webhook URLs, invalid confirmation thresholds, or missing cold address in
    /// hot auto-sweep mode.
    pub fn validate(&self) -> GatewayResult<()> {
        let _: SocketAddr = self.bind_addr().parse().map_err(|err| {
            GatewayError::Config(format!("invalid HOST:PORT '{}': {err}", self.bind_addr()))
        })?;

        if self.database_url.trim().is_empty() {
            return Err(GatewayError::Config(
                "DATABASE_URL must not be empty".to_string(),
            ));
        }

        validate_secret("API_SECRET_KEY", &self.api_secret_key)?;
        validate_secret("WEBHOOK_SECRET", &self.webhook_secret)?;

        validate_http_url(&self.monero_rpc_url, "MONERO_RPC_URL")?;

        if let Some(ref webhook_url) = self.default_webhook_url {
            validate_http_url(webhook_url, "DEFAULT_WEBHOOK_URL")?;
        }

        if self.required_confirmations == 0 {
            return Err(GatewayError::Config(
                "REQUIRED_CONFIRMATIONS must be >= 1 (0-conf is tracked as MEMPOOL)".to_string(),
            ));
        }

        if self.invoice_ttl_seconds == 0 {
            return Err(GatewayError::Config(
                "INVOICE_TTL_SECONDS must be >= 1".to_string(),
            ));
        }

        if self.scan_interval_seconds == 0 {
            return Err(GatewayError::Config(
                "SCAN_INTERVAL_SECONDS must be >= 1".to_string(),
            ));
        }

        if self.webhook_poll_interval_seconds == 0 {
            return Err(GatewayError::Config(
                "WEBHOOK_POLL_INTERVAL_SECONDS must be >= 1".to_string(),
            ));
        }

        if self.sweep_priority > 4 {
            return Err(GatewayError::Config(format!(
                "SWEEP_PRIORITY must be between 0 and 4, got {}",
                self.sweep_priority
            )));
        }

        if self.enable_auto_sweep {
            let cold = self.cold_wallet_address.as_deref().ok_or_else(|| {
                GatewayError::Config(
                    "COLD_WALLET_ADDRESS is required when ENABLE_AUTO_SWEEP=true".to_string(),
                )
            })?;
            validate_monero_address(cold).map_err(GatewayError::Config)?;
        } else if let Some(ref cold) = self.cold_wallet_address {
            validate_monero_address(cold).map_err(GatewayError::Config)?;
        }

        Ok(())
    }

    /// Returns the `HOST:PORT` string used to bind the TCP listener.
    #[must_use]
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Validates that a URL uses HTTP or HTTPS and contains a non-empty host.
///
/// # Errors
/// Returns [`GatewayError::Config`] if parsing fails, the scheme is not `http`/`https`,
/// or the host is absent.
pub fn validate_http_url(raw: &str, field_name: &str) -> GatewayResult<Url> {
    let parsed = Url::parse(raw)
        .map_err(|err| GatewayError::Config(format!("invalid {field_name} '{raw}': {err}")))?;

    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(GatewayError::Config(format!(
                "invalid {field_name} scheme '{other}': only http and https are allowed"
            )));
        }
    }

    if parsed.host_str().is_none() {
        return Err(GatewayError::Config(format!(
            "invalid {field_name} '{raw}': missing host"
        )));
    }

    Ok(parsed)
}

/// Validates structural properties of a Monero address (mainnet, stagenet, or testnet).
///
/// Checks:
/// - Length is `95` (standard primary address or subaddress) or `106` (integrated address).
/// - Leading character matches Monero network prefix bytes:
///   - Mainnet: `4` (primary/integrated), `8` (subaddress)
///   - Stagenet: `5` (primary/integrated), `7` (subaddress)
///   - Testnet: `9` / `A` (primary/integrated), `B` (subaddress)
/// - Every character belongs to the Monero Base58 alphabet.
///
/// # Errors
/// Returns a descriptive error string if any structural rule fails.
pub fn validate_monero_address(address: &str) -> Result<(), String> {
    let trimmed = address.trim();
    if trimmed != address || trimmed.is_empty() {
        return Err("Monero address must be non-empty without surrounding whitespace".to_string());
    }

    let len = trimmed.len();
    if len != 95 && len != 106 {
        return Err(format!(
            "invalid Monero address length {len}: expected 95 (standard/subaddress) or 106 (integrated)"
        ));
    }

    let valid_prefix = matches!(
        trimmed.chars().next(),
        Some('4' | '8' | '5' | '7' | '9' | 'A' | 'B')
    );
    if !valid_prefix {
        return Err(
            "invalid Monero address prefix: expected mainnet (4/8), stagenet (5/7), or testnet (9/A/B)"
                .to_string(),
        );
    }

    if !trimmed.chars().all(|c| MONERO_BASE58_ALPHABET.contains(c)) {
        return Err("Monero address contains invalid non-Base58 characters".to_string());
    }

    Ok(())
}

/// Validates that a cryptographic secret is non-empty, at least 32 bytes, and not an
/// unreplaced template placeholder.
fn validate_secret(name: &str, value: &str) -> GatewayResult<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(GatewayError::Config(format!("{name} must not be empty")));
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("replace-with-")
        || lower.starts_with("changeme")
        || lower.starts_with("example-")
    {
        return Err(GatewayError::Config(format!(
            "{name} still contains a placeholder value; generate a random 32-byte secret"
        )));
    }

    if trimmed.len() < 32 {
        return Err(GatewayError::Config(format!(
            "{name} must be at least 32 bytes long (got {})",
            trimmed.len()
        )));
    }

    Ok(())
}

fn env_or_default(key: &str, default: &str) -> String {
    match env::var(key) {
        Ok(val) if !val.trim().is_empty() => val,
        _ => default.to_string(),
    }
}

fn optional_non_empty_env(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn require_non_empty_env(key: &str) -> GatewayResult<String> {
    optional_non_empty_env(key)
        .ok_or_else(|| GatewayError::Config(format!("missing required env var {key}")))
}

fn parse_env_u16(key: &str, default: u16) -> GatewayResult<u16> {
    match optional_non_empty_env(key) {
        Some(raw) => raw
            .parse::<u16>()
            .map_err(|err| GatewayError::Config(format!("invalid {key} '{raw}': {err}"))),
        None => Ok(default),
    }
}

fn parse_env_u32(key: &str, default: u32) -> GatewayResult<u32> {
    match optional_non_empty_env(key) {
        Some(raw) => raw
            .parse::<u32>()
            .map_err(|err| GatewayError::Config(format!("invalid {key} '{raw}': {err}"))),
        None => Ok(default),
    }
}

fn parse_env_u64(key: &str, default: u64) -> GatewayResult<u64> {
    match optional_non_empty_env(key) {
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|err| GatewayError::Config(format!("invalid {key} '{raw}': {err}"))),
        None => Ok(default),
    }
}

fn parse_env_bool(key: &str, default: bool) -> GatewayResult<bool> {
    match optional_non_empty_env(key) {
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            _ => Err(GatewayError::Config(format!(
                "invalid boolean {key} '{raw}': expected true/false"
            ))),
        },
        None => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_valid_config() -> Config {
        Config {
            host: "127.0.0.1".to_string(),
            port: 8080,
            cors_allowed_origins: vec!["*".to_string()],
            database_url: "sqlite::memory:".to_string(),
            api_secret_key: "a".repeat(32),
            webhook_secret: "b".repeat(32),
            default_webhook_url: Some("https://bot.example.org/webhook".to_string()),
            monero_rpc_url: "http://127.0.0.1:18082/json_rpc".to_string(),
            monero_rpc_user: Some("rpcuser".to_string()),
            monero_rpc_pass: Some("super-secret-rpc-pass".to_string()),
            cold_wallet_address: None,
            enable_auto_sweep: false,
            sweep_priority: 0,
            required_confirmations: 2,
            invoice_ttl_seconds: 3600,
            scan_interval_seconds: 10,
            webhook_poll_interval_seconds: 5,
            log_format: LogFormat::Json,
        }
    }

    fn valid_mainnet_address() -> String {
        format!("4{}", "A".repeat(94))
    }

    #[test]
    fn debug_redacts_secrets() {
        let cfg = sample_valid_config();
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains(&"a".repeat(32)));
        assert!(!dbg.contains(&"b".repeat(32)));
        assert!(!dbg.contains("super-secret-rpc-pass"));
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn auto_sweep_requires_valid_cold_wallet_address() {
        let mut cfg = sample_valid_config();
        cfg.enable_auto_sweep = true;
        cfg.cold_wallet_address = None;
        assert!(cfg.validate().is_err());

        cfg.cold_wallet_address = Some("not-a-monero-address".to_string());
        assert!(cfg.validate().is_err());

        cfg.cold_wallet_address = Some(valid_mainnet_address());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn zero_confirmations_rejected() {
        let mut cfg = sample_valid_config();
        cfg.required_confirmations = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn invalid_sweep_priority_rejected() {
        let mut cfg = sample_valid_config();
        cfg.sweep_priority = 5;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn monero_address_validation_checks_prefixes_and_base58() {
        assert!(validate_monero_address(&format!("4{}", "2".repeat(94))).is_ok());
        assert!(validate_monero_address(&format!("8{}", "3".repeat(94))).is_ok());
        assert!(validate_monero_address(&format!("5{}", "4".repeat(94))).is_ok());
        assert!(validate_monero_address(&format!("7{}", "5".repeat(94))).is_ok());
        assert!(validate_monero_address(&format!("4{}", "3".repeat(105))).is_ok());
        // '0', 'O', 'I', 'l' are invalid in Base58
        assert!(validate_monero_address(&format!("40{}", "A".repeat(93))).is_err());
        assert!(validate_monero_address("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh").is_err());
    }

    #[test]
    fn rejects_weak_or_placeholder_secrets() {
        let mut cfg = sample_valid_config();
        cfg.api_secret_key = "short".to_string();
        assert!(cfg.validate().is_err());

        let mut cfg2 = sample_valid_config();
        cfg2.webhook_secret = "replace-with-at-least-32-bytes-of-secret".to_string();
        assert!(cfg2.validate().is_err());
    }
}
