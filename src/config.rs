//! Runtime configuration loading and security invariant validation.
//!
//! Configuration is sourced from environment variables (and optionally `.env` via `dotenvy`).
//! Sensitive fields (`api_secret_key`, `webhook_secret`, `monero_rpc_pass`) are redacted in
//! [`std::fmt::Debug`] so accidental debug formatting never leaks secrets into structured logs.

use std::{env, fmt, net::SocketAddr};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    error::{GatewayError, GatewayResult},
    security::url_policy::{WebhookUrlPolicy, validate_webhook_url_static},
};

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

/// Wallet custody mode enforced at startup and verified against `monero-wallet-rpc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletMode {
    /// Zero-trust watch-only wallet (`monero-wallet-rpc` must NOT hold a private spend key).
    ViewOnly,
    /// Hot transit wallet capable of signing `sweep_all` transactions to cold storage.
    HotWallet,
}

impl WalletMode {
    /// Returns canonical snake_case configuration representation (`"view_only"` or `"hot_wallet"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ViewOnly => "view_only",
            Self::HotWallet => "hot_wallet",
        }
    }

    /// Parses `WALLET_MODE` environment variable value (`view_only` or `hot_wallet`).
    fn parse(raw: &str) -> GatewayResult<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "view_only" | "view-only" => Ok(Self::ViewOnly),
            "hot_wallet" | "hot-wallet" => Ok(Self::HotWallet),
            other => Err(GatewayError::Config(format!(
                "invalid WALLET_MODE '{other}': expected 'view_only' or 'hot_wallet'"
            ))),
        }
    }
}

impl fmt::Display for WalletMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Target Monero network configured for the gateway (`MONERO_NETWORK`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroNetwork {
    /// Monero mainnet (`MONERO_NETWORK=mainnet`).
    #[default]
    Mainnet,
    /// Monero stagenet (`MONERO_NETWORK=stagenet`).
    Stagenet,
    /// Monero testnet (`MONERO_NETWORK=testnet`).
    Testnet,
}

impl MoneroNetwork {
    /// Returns canonical lowercase network name (`"mainnet"`, `"stagenet"`, or `"testnet"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Stagenet => "stagenet",
            Self::Testnet => "testnet",
        }
    }

    /// Parses `MONERO_NETWORK` environment variable value.
    fn parse(raw: &str) -> GatewayResult<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "stagenet" => Ok(Self::Stagenet),
            "testnet" => Ok(Self::Testnet),
            other => Err(GatewayError::Config(format!(
                "invalid MONERO_NETWORK '{other}': expected 'mainnet', 'stagenet', or 'testnet'"
            ))),
        }
    }
}

impl fmt::Display for MoneroNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Complete, validated configuration for `xmr-gateway`.
///
/// # Security Invariants
/// - `api_secret_key` and `webhook_secret` must be non-empty.
/// - `required_confirmations` must be `>= 1` so `CONFIRMED` never aliases `MEMPOOL` (`0-conf`).
/// - When `enable_auto_sweep == true`, `wallet_mode` must be `WalletMode::HotWallet` and
///   `cold_wallet_address` MUST be present and pass Monero address structural validation.
/// - `WalletMode::HotWallet` (and `ENABLE_AUTO_SWEEP=true`) requires a distinct, strong
///   `OPERATOR_API_KEY` (`XMR-AUDIT-004`).
/// - `WalletMode::HotWallet` requires `ENABLE_AUTO_SWEEP=true` unless
///   `ALLOW_HOT_WALLET_WITHOUT_SWEEP=true` is explicitly configured.
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
    /// Optional privileged operator secret key isolating sweep/recovery routes (`OPERATOR_API_KEY`).
    pub operator_api_key: Option<String>,
    /// Shared secret for HMAC-SHA256 webhook body signatures (`X-Signature-256`).
    pub webhook_secret: String,
    /// Optional fallback webhook URL used when invoice creation omits `callback_url`.
    pub default_webhook_url: Option<String>,
    /// Permit private/loopback/link-local webhook URLs (`false` in production; `true` for local dev).
    pub allow_private_webhooks: bool,
    /// Require `https://` scheme on all outbound webhook URLs.
    pub require_https_webhooks: bool,
    /// Target Monero network (`mainnet`, `stagenet`, or `testnet`) (`AUDIT-001`).
    pub monero_network: MoneroNetwork,
    /// Full HTTP/HTTPS URL to `monero-wallet-rpc` JSON-RPC endpoint.
    pub monero_rpc_url: String,
    /// Optional explicit `monerod` JSON-RPC URL (`MONERO_DAEMON_RPC_URL`) used for `get_info`
    /// height verification during incident resolution (`AUDIT-001`).
    pub monero_daemon_rpc_url: Option<String>,
    /// Optional RPC username for `MONERO_DAEMON_RPC_URL` Digest/Basic authentication (`AUDIT-001`).
    pub monero_daemon_rpc_user: Option<String>,
    /// Optional RPC password for `MONERO_DAEMON_RPC_URL` Digest/Basic authentication (`AUDIT-001`).
    pub monero_daemon_rpc_pass: Option<String>,
    /// Optional RPC username for `--rpc-login` Digest/Basic authentication.
    pub monero_rpc_user: Option<String>,
    /// Optional RPC password for `--rpc-login` Digest/Basic authentication.
    pub monero_rpc_pass: Option<String>,
    /// Explicit override allowing unauthenticated `monero-wallet-rpc` connections (`false` in production).
    pub allow_unauthenticated_rpc: bool,
    /// Explicit override allowing cleartext `http://` to non-loopback `MONERO_RPC_URL` hosts (`false` in production).
    pub allow_insecure_remote_rpc: bool,
    /// Destination Monero address for automated and manual sweeps.
    pub cold_wallet_address: Option<String>,
    /// Custody mode enforced against `monero-wallet-rpc` at startup (`view_only` | `hot_wallet`).
    pub wallet_mode: WalletMode,
    /// Whether `monero-wallet-rpc` connects to a trusted operator-owned daemon (`--trusted-daemon`).
    pub monero_trusted_daemon: bool,
    /// Explicit override permitting a hot wallet when `ENABLE_AUTO_SWEEP=false`.
    pub allow_hot_wallet_without_sweep: bool,
    /// Custody mode flag: `false` = View-Only Zero-Trust, `true` = Hot Auto-Sweep.
    pub enable_auto_sweep: bool,
    /// Monero transaction priority (`0..=4`) passed to `sweep_all`.
    pub sweep_priority: u32,
    /// Minimum block confirmations required before transitioning an invoice to `CONFIRMED`.
    pub required_confirmations: u64,
    /// Block confirmations required for full Monero lock/settlement finality (`SETTLED`, default `10`).
    pub settlement_confirmations: u64,
    /// Default invoice expiration window in seconds.
    pub invoice_ttl_seconds: u64,
    /// Interval in seconds between background scanner polls against `monero-wallet-rpc`.
    pub scan_interval_seconds: u64,
    /// Interval in seconds between background webhook retry polls.
    pub webhook_poll_interval_seconds: u64,
    /// Retention window in days for scanning terminal (`COMPLETED`/`SWEPT`/`EXPIRED`) subaddresses
    /// (`SUBADDRESS_MONITOR_DAYS`, default `0` = continuous/unbounded monitoring of all subaddresses).
    pub subaddress_monitor_days: u64,
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
            .field(
                "operator_api_key",
                &self.operator_api_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("webhook_secret", &"[REDACTED]")
            .field("default_webhook_url", &self.default_webhook_url)
            .field("allow_private_webhooks", &self.allow_private_webhooks)
            .field("require_https_webhooks", &self.require_https_webhooks)
            .field("monero_network", &self.monero_network)
            .field("monero_rpc_url", &self.monero_rpc_url)
            .field("monero_daemon_rpc_url", &self.monero_daemon_rpc_url)
            .field("monero_daemon_rpc_user", &self.monero_daemon_rpc_user)
            .field(
                "monero_daemon_rpc_pass",
                &self.monero_daemon_rpc_pass.as_ref().map(|_| "[REDACTED]"),
            )
            .field("monero_rpc_user", &self.monero_rpc_user)
            .field(
                "monero_rpc_pass",
                &self.monero_rpc_pass.as_ref().map(|_| "[REDACTED]"),
            )
            .field("allow_unauthenticated_rpc", &self.allow_unauthenticated_rpc)
            .field("allow_insecure_remote_rpc", &self.allow_insecure_remote_rpc)
            .field("cold_wallet_address", &self.cold_wallet_address)
            .field("wallet_mode", &self.wallet_mode)
            .field("monero_trusted_daemon", &self.monero_trusted_daemon)
            .field(
                "allow_hot_wallet_without_sweep",
                &self.allow_hot_wallet_without_sweep,
            )
            .field("enable_auto_sweep", &self.enable_auto_sweep)
            .field("sweep_priority", &self.sweep_priority)
            .field("required_confirmations", &self.required_confirmations)
            .field("settlement_confirmations", &self.settlement_confirmations)
            .field("invoice_ttl_seconds", &self.invoice_ttl_seconds)
            .field("scan_interval_seconds", &self.scan_interval_seconds)
            .field(
                "webhook_poll_interval_seconds",
                &self.webhook_poll_interval_seconds,
            )
            .field("subaddress_monitor_days", &self.subaddress_monitor_days)
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
        let operator_api_key = optional_non_empty_env("OPERATOR_API_KEY");
        let webhook_secret = require_non_empty_env("WEBHOOK_SECRET")?;
        let default_webhook_url = optional_non_empty_env("DEFAULT_WEBHOOK_URL");
        let allow_private_webhooks = parse_env_bool("ALLOW_PRIVATE_WEBHOOKS", false)?;
        let require_https_webhooks = parse_env_bool("REQUIRE_HTTPS_WEBHOOKS", false)?;
        let monero_network = MoneroNetwork::parse(&env_or_default("MONERO_NETWORK", "mainnet"))?;
        let monero_rpc_url = env_or_default("MONERO_RPC_URL", "http://127.0.0.1:18082/json_rpc");
        let monero_daemon_rpc_url = optional_non_empty_env("MONERO_DAEMON_RPC_URL");
        let monero_daemon_rpc_user = optional_non_empty_env("MONERO_DAEMON_RPC_USER");
        let monero_daemon_rpc_pass = optional_non_empty_env("MONERO_DAEMON_RPC_PASS");
        let monero_rpc_user = optional_non_empty_env("MONERO_RPC_USER");
        let monero_rpc_pass = optional_non_empty_env("MONERO_RPC_PASS");
        let allow_unauthenticated_rpc = parse_env_bool("ALLOW_UNAUTHENTICATED_RPC", false)?;
        let allow_insecure_remote_rpc = parse_env_bool("ALLOW_INSECURE_REMOTE_RPC", false)?;
        let cold_wallet_address = optional_non_empty_env("COLD_WALLET_ADDRESS");
        let enable_auto_sweep = parse_env_bool("ENABLE_AUTO_SWEEP", false)?;
        let wallet_mode = match optional_non_empty_env("WALLET_MODE") {
            Some(raw) => WalletMode::parse(&raw)?,
            None => {
                if enable_auto_sweep {
                    WalletMode::HotWallet
                } else {
                    WalletMode::ViewOnly
                }
            }
        };
        let monero_trusted_daemon = parse_env_bool("MONERO_TRUSTED_DAEMON", false)?;
        let allow_hot_wallet_without_sweep =
            parse_env_bool("ALLOW_HOT_WALLET_WITHOUT_SWEEP", false)?;
        let sweep_priority = parse_env_u32("SWEEP_PRIORITY", 0)?;
        let required_confirmations = parse_env_u64("REQUIRED_CONFIRMATIONS", 10)?;
        let settlement_confirmations = match optional_non_empty_env("SETTLEMENT_CONFIRMATIONS") {
            Some(raw) => raw.parse::<u64>().map_err(|err| {
                GatewayError::Config(format!("invalid SETTLEMENT_CONFIRMATIONS '{raw}': {err}"))
            })?,
            None => required_confirmations.max(10),
        };
        let invoice_ttl_seconds = parse_env_u64("INVOICE_TTL_SECONDS", 3600)?;
        let scan_interval_seconds = parse_env_u64("SCAN_INTERVAL_SECONDS", 10)?;
        let webhook_poll_interval_seconds = parse_env_u64("WEBHOOK_POLL_INTERVAL_SECONDS", 5)?;
        let subaddress_monitor_days = parse_env_u64("SUBADDRESS_MONITOR_DAYS", 0)?;
        let log_format = LogFormat::parse(&env_or_default("LOG_FORMAT", "json"))?;

        let config = Self {
            host,
            port,
            cors_allowed_origins,
            database_url,
            api_secret_key,
            operator_api_key,
            webhook_secret,
            default_webhook_url,
            allow_private_webhooks,
            require_https_webhooks,
            monero_network,
            monero_rpc_url,
            monero_daemon_rpc_url,
            monero_daemon_rpc_user,
            monero_daemon_rpc_pass,
            monero_rpc_user,
            monero_rpc_pass,
            allow_unauthenticated_rpc,
            allow_insecure_remote_rpc,
            cold_wallet_address,
            wallet_mode,
            monero_trusted_daemon,
            allow_hot_wallet_without_sweep,
            enable_auto_sweep,
            sweep_priority,
            required_confirmations,
            settlement_confirmations,
            invoice_ttl_seconds,
            scan_interval_seconds,
            webhook_poll_interval_seconds,
            subaddress_monitor_days,
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
        if let Some(ref op_key) = self.operator_api_key {
            validate_secret("OPERATOR_API_KEY", op_key)?;
            if crate::api::middleware::constant_time_key_match(op_key, &self.api_secret_key)
                || crate::api::middleware::constant_time_key_match(
                    op_key.trim(),
                    self.api_secret_key.trim(),
                )
            {
                return Err(GatewayError::Config(
                    "OPERATOR_API_KEY must differ from API_SECRET_KEY when configured (AUDIT-002)"
                        .to_string(),
                ));
            }
        }
        validate_secret("WEBHOOK_SECRET", &self.webhook_secret)?;

        let rpc_url = validate_http_url(&self.monero_rpc_url, "MONERO_RPC_URL")?;
        validate_rpc_security(
            &rpc_url,
            self.monero_rpc_user.as_deref(),
            self.monero_rpc_pass.as_deref(),
            self.allow_unauthenticated_rpc,
            self.allow_insecure_remote_rpc,
            "MONERO_RPC_URL",
            "MONERO_RPC_USER",
            "MONERO_RPC_PASS",
        )?;

        let daemon_url_trimmed = self
            .monero_daemon_rpc_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let has_daemon_user = self
            .monero_daemon_rpc_user
            .as_deref()
            .map(str::trim)
            .is_some_and(|s| !s.is_empty());
        let has_daemon_pass = self
            .monero_daemon_rpc_pass
            .as_deref()
            .map(str::trim)
            .is_some_and(|s| !s.is_empty());

        if let Some(daemon_url) = daemon_url_trimmed {
            let parsed_daemon_url = validate_http_url(daemon_url, "MONERO_DAEMON_RPC_URL")?;
            validate_rpc_security(
                &parsed_daemon_url,
                self.monero_daemon_rpc_user.as_deref(),
                self.monero_daemon_rpc_pass.as_deref(),
                self.allow_unauthenticated_rpc,
                self.allow_insecure_remote_rpc,
                "MONERO_DAEMON_RPC_URL",
                "MONERO_DAEMON_RPC_USER",
                "MONERO_DAEMON_RPC_PASS",
            )?;
        } else if has_daemon_user || has_daemon_pass {
            return Err(GatewayError::Config(
                "MONERO_DAEMON_RPC_USER and MONERO_DAEMON_RPC_PASS require MONERO_DAEMON_RPC_URL to be set"
                    .to_string(),
            ));
        }

        if let Some(ref webhook_url) = self.default_webhook_url {
            validate_webhook_url_static(
                webhook_url,
                "DEFAULT_WEBHOOK_URL",
                self.webhook_url_policy(),
            )
            .map_err(|e| GatewayError::Config(e.to_string()))?;
        }

        if self.required_confirmations == 0 {
            return Err(GatewayError::Config(
                "REQUIRED_CONFIRMATIONS must be >= 1 (0-conf is tracked as MEMPOOL)".to_string(),
            ));
        }

        if self.settlement_confirmations < self.required_confirmations {
            return Err(GatewayError::Config(
                "SETTLEMENT_CONFIRMATIONS must be >= REQUIRED_CONFIRMATIONS".to_string(),
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

        if (self.wallet_mode == WalletMode::HotWallet || self.enable_auto_sweep)
            && self.operator_api_key.is_none()
        {
            return Err(GatewayError::Config(
                "OPERATOR_API_KEY is required when WALLET_MODE=hot_wallet or ENABLE_AUTO_SWEEP=true (XMR-AUDIT-004)"
                    .to_string(),
            ));
        }

        if self.enable_auto_sweep && self.wallet_mode != WalletMode::HotWallet {
            return Err(GatewayError::Config(
                "ENABLE_AUTO_SWEEP=true requires WALLET_MODE=hot_wallet".to_string(),
            ));
        }

        if self.wallet_mode == WalletMode::HotWallet
            && !self.enable_auto_sweep
            && !self.allow_hot_wallet_without_sweep
        {
            return Err(GatewayError::Config(
                "WALLET_MODE=hot_wallet requires ENABLE_AUTO_SWEEP=true (or explicit ALLOW_HOT_WALLET_WITHOUT_SWEEP=true)"
                    .to_string(),
            ));
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

    /// Returns the configured [`WebhookUrlPolicy`] governing SSRF and HTTPS enforcement.
    #[must_use]
    pub const fn webhook_url_policy(&self) -> WebhookUrlPolicy {
        WebhookUrlPolicy {
            allow_private_webhooks: self.allow_private_webhooks,
            require_https_webhooks: self.require_https_webhooks,
        }
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

/// Validates RPC authentication and transport security policies (`XMR-031` / `AUDIT-001`).
#[allow(clippy::too_many_arguments)]
fn validate_rpc_security(
    rpc_url: &Url,
    rpc_user: Option<&str>,
    rpc_pass: Option<&str>,
    allow_unauthenticated_rpc: bool,
    allow_insecure_remote_rpc: bool,
    url_env_name: &str,
    user_env_name: &str,
    pass_env_name: &str,
) -> GatewayResult<()> {
    let user_opt = rpc_user.map(str::trim).filter(|s| !s.is_empty());
    let pass_opt = rpc_pass.map(str::trim).filter(|s| !s.is_empty());

    if user_opt.is_some() ^ pass_opt.is_some() {
        return Err(GatewayError::Config(format!(
            "{user_env_name} and {pass_env_name} must either both be set or both be omitted"
        )));
    }

    if !allow_unauthenticated_rpc {
        let user = user_opt.ok_or_else(|| {
            GatewayError::Config(format!(
                "{user_env_name} is required when ALLOW_UNAUTHENTICATED_RPC=false"
            ))
        })?;
        let pass = pass_opt.ok_or_else(|| {
            GatewayError::Config(format!(
                "{pass_env_name} is required when ALLOW_UNAUTHENTICATED_RPC=false"
            ))
        })?;
        if user == pass {
            return Err(GatewayError::Config(format!(
                "{pass_env_name} must differ from {user_env_name}"
            )));
        }
        let lower = pass.to_ascii_lowercase();
        if lower.starts_with("replace-with-")
            || lower.starts_with("changeme")
            || lower.starts_with("example-")
            || matches!(lower.as_str(), "password" | "admin" | "123456" | "monero")
        {
            return Err(GatewayError::Config(format!(
                "{pass_env_name} contains a placeholder or weak password; generate a random secret"
            )));
        }
        if pass.len() < 16 {
            return Err(GatewayError::Config(format!(
                "{pass_env_name} must be at least 16 characters long (got {})",
                pass.len()
            )));
        }
    }

    if !allow_insecure_remote_rpc && rpc_url.scheme() == "http" {
        let host = rpc_url.host_str().unwrap_or_default();
        let host_unbracketed = host.trim_start_matches('[').trim_end_matches(']');
        let is_loopback = host_unbracketed.eq_ignore_ascii_case("localhost")
            || host_unbracketed
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        if !is_loopback {
            return Err(GatewayError::Config(format!(
                "cleartext HTTP {url_env_name} targeting non-loopback host '{host}' is forbidden unless ALLOW_INSECURE_REMOTE_RPC=true (use https:// or an SSH/WireGuard loopback tunnel)"
            )));
        }
    }

    Ok(())
}

/// Validates structural and cryptographic properties of a Monero address (`XMR-030`).
///
/// Checks:
/// - No leading/trailing whitespace and exact length `95` (standard/subaddress) or `106` (integrated).
/// - Strictly valid Monero Base58 block decoding into `69` or `77` bytes.
/// - Valid Monero network prefix byte:
///   - Mainnet: `18` (primary), `42` (subaddress), `19` (integrated)
///   - Stagenet: `24` (primary), `36` (subaddress), `25` (integrated)
///   - Testnet: `53` (primary), `63` (subaddress), `54` (integrated)
/// - Cryptographic 4-byte Keccak-256 checksum matches the payload prefix.
///
/// # Errors
/// Returns a descriptive error string if any structural or cryptographic checksum check fails.
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

    let decoded = decode_monero_base58(trimmed)?;
    let expected_byte_len = if len == 95 { 69 } else { 77 };
    if decoded.len() != expected_byte_len {
        return Err(format!(
            "invalid decoded Monero address byte length {}: expected {expected_byte_len}",
            decoded.len()
        ));
    }

    let net_byte = decoded[0];
    let valid_network = match len {
        95 => matches!(net_byte, 18 | 42 | 24 | 36 | 53 | 63),
        106 => matches!(net_byte, 19 | 25 | 54),
        _ => false,
    };
    if !valid_network {
        return Err(format!(
            "invalid Monero network prefix byte {net_byte} for {len}-char address"
        ));
    }

    let (payload, checksum) = decoded.split_at(decoded.len() - 4);
    let expected_hash = keccak256(payload);
    if checksum != &expected_hash[..4] {
        return Err("Monero address failed Keccak-256 4-byte checksum verification".to_string());
    }

    Ok(())
}

/// Encodes a deterministic checksum-valid Monero Base58 address from network tag and public keys.
///
/// Intended for test fixtures across mainnet (`18`/`42`/`19`), stagenet (`24`/`36`/`25`), and testnet.
#[must_use]
pub fn encode_monero_base58_address(
    network_byte: u8,
    spend_key: &[u8; 32],
    view_key: &[u8; 32],
    payment_id: Option<&[u8; 8]>,
) -> String {
    let mut payload = Vec::with_capacity(if payment_id.is_some() { 77 } else { 69 });
    payload.push(network_byte);
    payload.extend_from_slice(spend_key);
    payload.extend_from_slice(view_key);
    if let Some(pid) = payment_id {
        payload.extend_from_slice(pid);
    }
    let checksum = keccak256(&payload);
    payload.extend_from_slice(&checksum[..4]);
    encode_monero_base58(&payload)
}

fn monero_encoded_block_len(byte_len: usize) -> Option<usize> {
    match byte_len {
        0 => Some(0),
        1 => Some(2),
        2 => Some(3),
        3 => Some(5),
        4 => Some(6),
        5 => Some(7),
        6 => Some(9),
        7 => Some(10),
        8 => Some(11),
        _ => None,
    }
}

fn monero_decoded_block_len(char_len: usize) -> Option<usize> {
    match char_len {
        0 => Some(0),
        2 => Some(1),
        3 => Some(2),
        5 => Some(3),
        6 => Some(4),
        7 => Some(5),
        9 => Some(6),
        10 => Some(7),
        11 => Some(8),
        _ => None,
    }
}

fn decode_monero_base58(input: &str) -> Result<Vec<u8>, String> {
    let bytes = input.as_bytes();
    let alphabet = MONERO_BASE58_ALPHABET.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() / 11 + 1) * 8);

    for chunk in bytes.chunks(11) {
        let out_bytes = monero_decoded_block_len(chunk.len()).ok_or_else(|| {
            format!(
                "invalid Monero Base58 block character length {}",
                chunk.len()
            )
        })?;
        let mut acc: u64 = 0;
        for &ch in chunk {
            let digit = alphabet.iter().position(|&a| a == ch).ok_or_else(|| {
                "Monero address contains invalid non-Base58 characters".to_string()
            })? as u64;
            acc = acc
                .checked_mul(58)
                .and_then(|v| v.checked_add(digit))
                .ok_or_else(|| "Monero Base58 block overflow".to_string())?;
        }
        if out_bytes < 8 && (acc >> (out_bytes * 8)) != 0 {
            return Err("non-canonical Monero Base58 tail block".to_string());
        }
        let be = acc.to_be_bytes();
        out.extend_from_slice(&be[8 - out_bytes..]);
    }

    Ok(out)
}

fn encode_monero_base58(data: &[u8]) -> String {
    let alphabet = MONERO_BASE58_ALPHABET.as_bytes();
    let mut out = String::with_capacity((data.len() / 8 + 1) * 11);

    for chunk in data.chunks(8) {
        let char_len = monero_encoded_block_len(chunk.len()).unwrap_or(11);
        let mut be = [0_u8; 8];
        be[8 - chunk.len()..].copy_from_slice(chunk);
        let mut acc = u64::from_be_bytes(be);
        let mut block = vec![b'1'; char_len];
        for idx in (0..char_len).rev() {
            let rem = usize::try_from(acc % 58).unwrap_or(0);
            block[idx] = alphabet[rem];
            acc /= 58;
        }
        out.push_str(&String::from_utf8_lossy(&block));
    }

    out
}

/// Computes original Keccak-256 (`0x01` domain padding, NOT FIPS-202 SHA3-256) used by Monero.
#[must_use]
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    const RATE_BYTES: usize = 136;
    const KECCAK_RC: [u64; 24] = [
        0x0000_0000_0000_0001,
        0x0000_0000_0000_8082,
        0x8000_0000_0000_808a,
        0x8000_0000_8000_8000,
        0x0000_0000_0000_808b,
        0x0000_0000_8000_0001,
        0x8000_0000_8000_8081,
        0x8000_0000_0000_8009,
        0x0000_0000_0000_008a,
        0x0000_0000_0000_0088,
        0x0000_0000_8000_8009,
        0x0000_0000_8000_000a,
        0x0000_0000_8000_808b,
        0x8000_0000_0000_008b,
        0x8000_0000_0000_8089,
        0x8000_0000_0000_8003,
        0x8000_0000_0000_8002,
        0x8000_0000_0000_0080,
        0x0000_0000_0000_800a,
        0x8000_0000_8000_000a,
        0x8000_0000_8000_8081,
        0x8000_0000_0000_8080,
        0x0000_0000_8000_0001,
        0x8000_0000_8000_8008,
    ];
    const RHO: [u32; 25] = [
        0, 1, 62, 28, 27, // y = 0
        36, 44, 6, 55, 20, // y = 1
        3, 10, 43, 25, 39, // y = 2
        41, 45, 15, 21, 8, // y = 3
        18, 2, 61, 56, 14, // y = 4
    ];

    fn keccak_f1600(state: &mut [u64; 25]) {
        for &rc in &KECCAK_RC {
            let mut c = [0_u64; 5];
            for x in 0..5 {
                c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
            for x in 0..5 {
                let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
                for y in 0..5 {
                    state[x + 5 * y] ^= d;
                }
            }

            let mut b = [0_u64; 25];
            for y in 0..5 {
                for x in 0..5 {
                    let idx = x + 5 * y;
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = state[idx].rotate_left(RHO[idx]);
                }
            }

            for y in 0..5 {
                for x in 0..5 {
                    state[x + 5 * y] =
                        b[x + 5 * y] ^ ((!b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y]);
                }
            }

            state[0] ^= rc;
        }
    }

    let mut state = [0_u64; 25];
    let mut padded = Vec::with_capacity(input.len() + RATE_BYTES);
    padded.extend_from_slice(input);
    padded.push(0x01);
    let rem = padded.len() % RATE_BYTES;
    if rem != 0 {
        padded.resize(padded.len() + (RATE_BYTES - rem), 0);
    }
    if let Some(last) = padded.last_mut() {
        *last |= 0x80;
    }

    let (blocks, _) = padded.as_chunks::<RATE_BYTES>();
    for block in blocks {
        let (lanes, _) = block.as_chunks::<8>();
        for (word_idx, lane) in lanes.iter().enumerate() {
            state[word_idx] ^= u64::from_le_bytes(*lane);
        }
        keccak_f1600(&mut state);
    }

    let mut out = [0_u8; 32];
    for (i, &word) in state.iter().take(4).enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    out
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
            operator_api_key: None,
            webhook_secret: "b".repeat(32),
            default_webhook_url: Some("https://bot.example.org/webhook".to_string()),
            allow_private_webhooks: false,
            require_https_webhooks: false,
            monero_network: MoneroNetwork::Mainnet,
            monero_rpc_url: "http://127.0.0.1:18082/json_rpc".to_string(),
            monero_daemon_rpc_url: None,
            monero_daemon_rpc_user: None,
            monero_daemon_rpc_pass: None,
            monero_rpc_user: Some("rpcuser".to_string()),
            monero_rpc_pass: Some("super-secret-rpc-pass".to_string()),
            allow_unauthenticated_rpc: false,
            allow_insecure_remote_rpc: false,
            cold_wallet_address: None,
            wallet_mode: WalletMode::ViewOnly,
            monero_trusted_daemon: false,
            allow_hot_wallet_without_sweep: false,
            enable_auto_sweep: false,
            sweep_priority: 0,
            required_confirmations: 10,
            settlement_confirmations: 10,
            invoice_ttl_seconds: 3600,
            scan_interval_seconds: 10,
            webhook_poll_interval_seconds: 5,
            subaddress_monitor_days: 0,
            log_format: LogFormat::Json,
        }
    }

    fn valid_mainnet_address() -> String {
        encode_monero_base58_address(18, &[0x11; 32], &[0x22; 32], None)
    }

    #[test]
    fn debug_redacts_secrets() {
        let mut cfg = sample_valid_config();
        cfg.monero_daemon_rpc_pass = Some("daemon-super-secret-pass".to_string());
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains(&"a".repeat(32)));
        assert!(!dbg.contains(&"b".repeat(32)));
        assert!(!dbg.contains("super-secret-rpc-pass"));
        assert!(!dbg.contains("daemon-super-secret-pass"));
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn auto_sweep_requires_valid_cold_wallet_address() {
        let mut cfg = sample_valid_config();
        cfg.enable_auto_sweep = true;
        cfg.wallet_mode = WalletMode::HotWallet;
        cfg.operator_api_key = Some("c".repeat(32));
        cfg.cold_wallet_address = None;
        assert!(cfg.validate().is_err());

        cfg.cold_wallet_address = Some("not-a-monero-address".to_string());
        assert!(cfg.validate().is_err());

        cfg.cold_wallet_address = Some(valid_mainnet_address());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn wallet_mode_invariants_enforced() {
        let mut cfg = sample_valid_config();
        cfg.enable_auto_sweep = true;
        cfg.wallet_mode = WalletMode::ViewOnly;
        cfg.operator_api_key = Some("c".repeat(32));
        cfg.cold_wallet_address = Some(valid_mainnet_address());
        assert!(cfg.validate().is_err());

        let mut cfg2 = sample_valid_config();
        cfg2.wallet_mode = WalletMode::HotWallet;
        cfg2.operator_api_key = Some("c".repeat(32));
        cfg2.enable_auto_sweep = false;
        cfg2.allow_hot_wallet_without_sweep = false;
        assert!(cfg2.validate().is_err());

        cfg2.allow_hot_wallet_without_sweep = true;
        assert!(cfg2.validate().is_ok());
    }

    #[test]
    fn hot_wallet_requires_distinct_operator_api_key_xmr_audit_004() {
        // 1) view_only without OPERATOR_API_KEY remains valid (single-tenant fallback)
        let view_only = sample_valid_config();
        assert_eq!(view_only.wallet_mode, WalletMode::ViewOnly);
        assert!(view_only.operator_api_key.is_none());
        assert!(view_only.validate().is_ok());

        // 2) hot_wallet + enable_auto_sweep without OPERATOR_API_KEY MUST fail closed
        let mut hot_sweep = sample_valid_config();
        hot_sweep.wallet_mode = WalletMode::HotWallet;
        hot_sweep.enable_auto_sweep = true;
        hot_sweep.cold_wallet_address = Some(valid_mainnet_address());
        hot_sweep.operator_api_key = None;
        let err = hot_sweep.validate().unwrap_err();
        assert!(
            err.to_string().contains("OPERATOR_API_KEY is required"),
            "expected mandatory OPERATOR_API_KEY error, got: {err}"
        );

        // 3) hot_wallet + allow_hot_wallet_without_sweep without OPERATOR_API_KEY MUST fail closed
        let mut hot_no_sweep = sample_valid_config();
        hot_no_sweep.wallet_mode = WalletMode::HotWallet;
        hot_no_sweep.enable_auto_sweep = false;
        hot_no_sweep.allow_hot_wallet_without_sweep = true;
        hot_no_sweep.operator_api_key = None;
        assert!(hot_no_sweep.validate().is_err());

        // 4) hot_wallet with OPERATOR_API_KEY identical to API_SECRET_KEY MUST fail closed
        hot_sweep.operator_api_key = Some(hot_sweep.api_secret_key.clone());
        assert!(hot_sweep.validate().is_err());

        // 5) hot_wallet with distinct strong OPERATOR_API_KEY succeeds
        hot_sweep.operator_api_key = Some("c".repeat(32));
        assert!(hot_sweep.validate().is_ok());
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
    fn monero_address_validation_checks_keccak_checksum_and_networks() {
        // Known empty Keccak-256 test vector (distinct from FIPS-202 SHA3-256)
        assert_eq!(
            hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );

        // Real Monero mainnet subaddress from protocol test vector
        assert!(validate_monero_address(
            "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H"
        ).is_ok());

        // Generated checksum-valid mainnet, subaddress, stagenet, testnet, and integrated addresses
        let mainnet = encode_monero_base58_address(18, &[0x11; 32], &[0x22; 32], None);
        let subaddr = encode_monero_base58_address(42, &[0x33; 32], &[0x44; 32], None);
        let stagenet = encode_monero_base58_address(24, &[0x55; 32], &[0x66; 32], None);
        let stage_sub = encode_monero_base58_address(36, &[0x77; 32], &[0x88; 32], None);
        let integrated =
            encode_monero_base58_address(19, &[0x11; 32], &[0x22; 32], Some(&[0xaa; 8]));

        assert!(validate_monero_address(&mainnet).is_ok());
        assert!(validate_monero_address(&subaddr).is_ok());
        assert!(validate_monero_address(&stagenet).is_ok());
        assert!(validate_monero_address(&stage_sub).is_ok());
        assert!(validate_monero_address(&integrated).is_ok());

        // Single-character mutation in valid address MUST fail Keccak-256 checksum check (XMR-030)
        let mut mutated = mainnet.clone();
        let last = mutated.pop().unwrap();
        mutated.push(if last == 'A' { 'B' } else { 'A' });
        assert!(validate_monero_address(&mutated).is_err());

        // Repeated dummy Base58 strings with fake prefixes MUST fail checksum validation
        assert!(validate_monero_address(&format!("4{}", "2".repeat(94))).is_err());
        assert!(validate_monero_address(&format!("40{}", "A".repeat(93))).is_err());
        assert!(validate_monero_address("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh").is_err());
    }

    #[test]
    fn rpc_auth_and_cleartext_remote_policy_enforced() {
        // XMR-031: Missing RPC credentials fails closed when ALLOW_UNAUTHENTICATED_RPC=false
        let mut no_auth = sample_valid_config();
        no_auth.monero_rpc_user = None;
        no_auth.monero_rpc_pass = None;
        assert!(no_auth.validate().is_err());

        // Explicit opt-in permits unauthenticated loopback RPC (e.g. local isolated tests)
        no_auth.allow_unauthenticated_rpc = true;
        assert!(no_auth.validate().is_ok());

        // XMR-031: Non-loopback cleartext HTTP RPC rejected unless explicitly overridden
        let mut remote_http = sample_valid_config();
        remote_http.monero_rpc_url = "http://192.168.1.50:18082/json_rpc".to_string();
        assert!(remote_http.validate().is_err());

        // TLS remote RPC is allowed
        remote_http.monero_rpc_url = "https://rpc.internal.example:18082/json_rpc".to_string();
        assert!(remote_http.validate().is_ok());
    }

    #[test]
    fn daemon_rpc_security_policy_enforced_audit_001() {
        // Unpaired daemon user/pass or missing MONERO_DAEMON_RPC_URL rejected
        let mut orphan_creds = sample_valid_config();
        orphan_creds.monero_daemon_rpc_user = Some("daemon_user".to_string());
        orphan_creds.monero_daemon_rpc_pass = Some("daemon-secret-pass-012345".to_string());
        assert!(orphan_creds.validate().is_err());

        let mut unpaired = sample_valid_config();
        unpaired.allow_unauthenticated_rpc = true;
        unpaired.monero_daemon_rpc_url = Some("http://127.0.0.1:18081/json_rpc".to_string());
        unpaired.monero_daemon_rpc_user = Some("daemon_user".to_string());
        unpaired.monero_daemon_rpc_pass = None;
        assert!(unpaired.validate().is_err());

        // Non-loopback cleartext HTTP MONERO_DAEMON_RPC_URL rejected
        let mut remote_daemon_http = sample_valid_config();
        remote_daemon_http.monero_daemon_rpc_url =
            Some("http://10.0.0.25:18081/json_rpc".to_string());
        remote_daemon_http.monero_daemon_rpc_user = Some("daemon_user".to_string());
        remote_daemon_http.monero_daemon_rpc_pass = Some("daemon-secret-pass-012345".to_string());
        assert!(remote_daemon_http.validate().is_err());

        // HTTPS non-loopback MONERO_DAEMON_RPC_URL with valid credentials succeeds
        remote_daemon_http.monero_daemon_rpc_url =
            Some("https://node.internal.example:18081/json_rpc".to_string());
        assert!(remote_daemon_http.validate().is_ok());

        // Empty daemon credentials rejected when ALLOW_UNAUTHENTICATED_RPC=false
        let mut no_daemon_auth = sample_valid_config();
        no_daemon_auth.monero_daemon_rpc_url = Some("http://127.0.0.1:18081/json_rpc".to_string());
        assert!(no_daemon_auth.validate().is_err());
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

    #[test]
    fn rejects_operator_api_key_identical_to_api_secret_key_audit_002() {
        let mut same = sample_valid_config();
        same.operator_api_key = Some(same.api_secret_key.clone());
        let err = same.validate().unwrap_err();
        assert!(
            err.to_string().contains("OPERATOR_API_KEY must differ"),
            "expected distinct key error, got: {err}"
        );

        // Whitespace-padded duplicate must also be rejected
        let mut padded = sample_valid_config();
        padded.operator_api_key = Some(format!(" {} ", padded.api_secret_key));
        assert!(padded.validate().is_err());

        // Distinct >= 32-byte operator key succeeds
        let mut distinct = sample_valid_config();
        distinct.operator_api_key = Some("c".repeat(32));
        assert!(distinct.validate().is_ok());
    }
}
