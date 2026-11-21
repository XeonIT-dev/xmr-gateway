//! SSRF and DNS-rebinding protections for merchant-supplied webhook `callback_url` targets.
//!
//! # Threat Model & Defenses
//! Authenticated API callers supply `callback_url` when creating invoices. Without strict
//! egress validation, a compromised caller could probe loopback services (`127.0.0.1:18082`
//! `monero-wallet-rpc`), cloud instance metadata endpoints (`169.254.169.254`), or internal
//! RFC1918 subnets, or abuse DNS rebinding / HTTP `3xx` redirects to pivot into internal hosts.
//!
//! Enforced controls:
//! 1. Scheme allowlist (`http`/`https`, or strictly `https` when `REQUIRE_HTTPS_WEBHOOKS=true`).
//! 2. IP literal and DNS-resolution rejection of loopback, private, link-local, CGNAT,
//!    multicast, broadcast, unspecified, reserved, and IPv4-mapped internal addresses unless
//!    `ALLOW_PRIVATE_WEBHOOKS=true` is explicitly configured for local testing.
//! 3. Connection-time address pinning (`ResolvedWebhookTarget`) passed to `reqwest` via
//!    `resolve_to_addrs` so DNS rebinding between validation and TCP connect cannot occur.
//! 4. Redirect policy set to `reqwest::redirect::Policy::none()` on outbound webhook clients.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use url::{Host, Url};

use crate::error::{GatewayError, GatewayResult};

/// Policy flags governing outbound webhook URL validation and DNS resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WebhookUrlPolicy {
    /// Whether loopback, RFC1918 private, link-local, and local hostnames are permitted.
    pub allow_private_webhooks: bool,
    /// Whether only `https://` URLs are permitted (disallows cleartext `http://`).
    pub require_https_webhooks: bool,
}

/// Validated outbound webhook target together with pinned socket addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedWebhookTarget {
    /// Canonical parsed target URL.
    pub url: Url,
    /// Target hostname or IP string.
    pub host: String,
    /// Target TCP port.
    pub port: u16,
    /// Validated socket addresses to pin onto the HTTP client.
    pub resolved_addrs: Vec<SocketAddr>,
    /// `true` when the URL host is already a literal IP address rather than a DNS domain.
    pub is_ip_literal: bool,
}

/// Returns `true` if `ip` belongs to a loopback, private, link-local, CGNAT, multicast,
/// broadcast, unspecified, reserved, or internal IP range unsuitable for untrusted egress.
#[must_use]
pub fn is_prohibited_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let is_cgnat = octets[0] == 100 && (octets[1] & 0b1100_0000) == 64;
            let is_benchmark = octets[0] == 198 && (octets[1] == 18 || octets[1] == 19);
            let is_reserved = octets[0] >= 240;

            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || octets[0] == 0
                || is_cgnat
                || is_benchmark
                || is_reserved
        }
        IpAddr::V6(v6) => is_prohibited_ipv6(v6),
    }
}

fn is_prohibited_ipv6(v6: Ipv6Addr) -> bool {
    if let Some(mapped_v4) = v6.to_ipv4_mapped() {
        return is_prohibited_ip(IpAddr::V4(mapped_v4));
    }

    let segments = v6.segments();
    // Catch deprecated IPv4-compatible IPv6 form (::a.b.c.d) as well as :: and ::1.
    if segments[0..6] == [0, 0, 0, 0, 0, 0] {
        let compat_v4 = std::net::Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        );
        if v6.is_unspecified() || v6.is_loopback() || is_prohibited_ip(IpAddr::V4(compat_v4)) {
            return true;
        }
    }

    let is_unique_local = (segments[0] & 0xfe00) == 0xfc00; // fc00::/7
    let is_link_local = (segments[0] & 0xffc0) == 0xfe80; // fe80::/10
    let is_site_local = (segments[0] & 0xffc0) == 0xfec0; // fec0::/10 (deprecated RFC 3879 site-local)

    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || is_unique_local
        || is_link_local
        || is_site_local
}

/// Validates syntactic properties, scheme, embedded credentials, and static host/IP rules for
/// an outbound webhook URL without performing network DNS I/O.
///
/// # Errors
/// Returns [`GatewayError::Validation`] if the URL is malformed, violates scheme policy, contains
/// embedded userinfo, or names a prohibited private/internal IP or local domain when
/// `policy.allow_private_webhooks == false`.
pub fn validate_webhook_url_static(
    raw: &str,
    field_name: &str,
    policy: WebhookUrlPolicy,
) -> GatewayResult<Url> {
    let parsed = Url::parse(raw)
        .map_err(|err| GatewayError::Validation(format!("invalid {field_name} '{raw}': {err}")))?;

    match parsed.scheme() {
        "https" => {}
        "http" if !policy.require_https_webhooks => {}
        "http" => {
            return Err(GatewayError::Validation(format!(
                "invalid {field_name} scheme 'http': HTTPS is required (REQUIRE_HTTPS_WEBHOOKS=true)"
            )));
        }
        other => {
            return Err(GatewayError::Validation(format!(
                "invalid {field_name} scheme '{other}': only http and https are allowed"
            )));
        }
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(GatewayError::Validation(format!(
            "invalid {field_name}: embedded URL credentials are forbidden"
        )));
    }

    let host = parsed.host().ok_or_else(|| {
        GatewayError::Validation(format!("invalid {field_name} '{raw}': missing host"))
    })?;

    if !policy.allow_private_webhooks {
        match host {
            Host::Ipv4(v4) => {
                if is_prohibited_ip(IpAddr::V4(v4)) {
                    return Err(GatewayError::Validation(format!(
                        "{field_name} target IP '{v4}' is blocked by SSRF policy (set ALLOW_PRIVATE_WEBHOOKS=true only for local testing)"
                    )));
                }
            }
            Host::Ipv6(v6) => {
                if is_prohibited_ip(IpAddr::V6(v6)) {
                    return Err(GatewayError::Validation(format!(
                        "{field_name} target IPv6 '{v6}' is blocked by SSRF policy (set ALLOW_PRIVATE_WEBHOOKS=true only for local testing)"
                    )));
                }
            }
            Host::Domain(domain) => {
                let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
                if normalized.is_empty()
                    || normalized == "localhost"
                    || normalized.ends_with(".localhost")
                    || normalized.ends_with(".local")
                    || normalized.ends_with(".internal")
                {
                    return Err(GatewayError::Validation(format!(
                        "{field_name} host '{domain}' is blocked by SSRF policy"
                    )));
                }
            }
        }
    }

    Ok(parsed)
}

/// Validates an already-resolved set of socket addresses for `host` under `policy`.
///
/// # Errors
/// Returns [`GatewayError::Validation`] if no addresses were resolved or any resolved IP belongs
/// to a prohibited range when `policy.allow_private_webhooks == false`.
pub fn validate_resolved_addrs(
    field_name: &str,
    host: &str,
    addrs: &[SocketAddr],
    policy: WebhookUrlPolicy,
) -> GatewayResult<()> {
    if addrs.is_empty() {
        return Err(GatewayError::Validation(format!(
            "{field_name} host '{host}' did not resolve to any IP addresses"
        )));
    }

    if !policy.allow_private_webhooks {
        for addr in addrs {
            if is_prohibited_ip(addr.ip()) {
                return Err(GatewayError::Validation(format!(
                    "{field_name} host '{host}' resolved to prohibited IP '{}' (blocked by SSRF policy)",
                    addr.ip()
                )));
            }
        }
    }

    Ok(())
}

/// Performs static URL validation AND asynchronous DNS resolution, rejecting any domain whose
/// DNS records resolve to private/loopback/link-local/reserved IPs and returning the resolved
/// [`SocketAddr`] list for HTTP connection pinning against DNS rebinding.
///
/// # Errors
/// Returns [`GatewayError::Validation`] on policy violation or DNS resolution failure.
pub async fn resolve_and_validate_webhook_url(
    raw: &str,
    field_name: &str,
    policy: WebhookUrlPolicy,
) -> GatewayResult<ValidatedWebhookTarget> {
    let parsed = validate_webhook_url_static(raw, field_name, policy)?;
    let port = parsed.port_or_known_default().ok_or_else(|| {
        GatewayError::Validation(format!("invalid {field_name} '{raw}': missing port"))
    })?;
    let host_str = parsed
        .host_str()
        .ok_or_else(|| GatewayError::Validation(format!("invalid {field_name}: missing host")))?
        .to_string();

    match parsed.host() {
        Some(Host::Ipv4(v4)) => Ok(ValidatedWebhookTarget {
            url: parsed,
            host: host_str,
            port,
            resolved_addrs: vec![SocketAddr::new(IpAddr::V4(v4), port)],
            is_ip_literal: true,
        }),
        Some(Host::Ipv6(v6)) => Ok(ValidatedWebhookTarget {
            url: parsed,
            host: host_str,
            port,
            resolved_addrs: vec![SocketAddr::new(IpAddr::V6(v6), port)],
            is_ip_literal: true,
        }),
        Some(Host::Domain(domain)) => {
            let domain_owned = domain.to_string();
            let resolved: Vec<SocketAddr> = tokio::net::lookup_host((domain_owned.as_str(), port))
                .await
                .map_err(|err| {
                    GatewayError::Validation(format!(
                        "DNS lookup failed for {field_name} host '{domain_owned}': {err}"
                    ))
                })?
                .collect();

            validate_resolved_addrs(field_name, &domain_owned, &resolved, policy)?;

            Ok(ValidatedWebhookTarget {
                url: parsed,
                host: domain_owned,
                port,
                resolved_addrs: resolved,
                is_ip_literal: false,
            })
        }
        None => Err(GatewayError::Validation(format!(
            "invalid {field_name} '{raw}': missing host"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[tokio::test]
    async fn blocks_private_loopback_link_local_and_v6_urls_by_default() {
        let strict = WebhookUrlPolicy {
            allow_private_webhooks: false,
            require_https_webhooks: false,
        };

        let blocked = [
            "http://127.0.0.1:9000/webhooks/monero",
            "http://127.0.0.42:8080/hook",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/internal",
            "http://172.16.5.4/internal",
            "http://192.168.1.10/internal",
            "http://100.64.0.1/cgnat",
            "http://0.0.0.0:8080/zero",
            "http://[::1]:9000/hook",
            "http://[fc00::1]/hook",
            "http://[fd12:3456:789a::1]/hook",
            "http://[fe80::1]/hook",
            "http://[fec0::1]/hook",
            "http://[feff::ffff]/hook",
            "http://[::ffff:127.0.0.1]:9000/hook",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://localhost:9000/hook",
            "http://metadata.google.internal/computeMetadata/v1/",
            "ftp://example.com/hook",
            "https://user:pass@example.com/hook",
        ];

        for target in blocked {
            let res = resolve_and_validate_webhook_url(target, "callback_url", strict).await;
            assert!(
                res.is_err(),
                "expected SSRF policy to reject '{target}', but got Ok"
            );
        }

        // Public IP literal succeeds under strict policy
        assert!(
            resolve_and_validate_webhook_url(
                "https://93.184.216.34/webhook",
                "callback_url",
                strict
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn allows_private_and_loopback_when_allow_private_webhooks_is_true() {
        let permissive = WebhookUrlPolicy {
            allow_private_webhooks: true,
            require_https_webhooks: false,
        };

        for target in [
            "http://127.0.0.1:9000/webhooks/monero",
            "http://10.0.0.1:8080/hook",
            "http://[::1]:9000/hook",
            "http://[fc00::1]/hook",
        ] {
            let res = resolve_and_validate_webhook_url(target, "callback_url", permissive).await;
            assert!(
                res.is_ok(),
                "expected ALLOW_PRIVATE_WEBHOOKS=true to permit '{target}': {res:?}"
            );
        }
    }

    #[test]
    fn enforces_https_requirement_and_blocks_dns_rebinding_addrs() {
        let https_only = WebhookUrlPolicy {
            allow_private_webhooks: false,
            require_https_webhooks: true,
        };

        assert!(
            validate_webhook_url_static("http://example.com/hook", "callback_url", https_only)
                .is_err()
        );
        assert!(
            validate_webhook_url_static("https://example.com/hook", "callback_url", https_only)
                .is_ok()
        );

        // Simulate DNS resolving an external-looking domain to an internal IP
        let rebind_addrs = [SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            443,
        )];
        assert!(
            validate_resolved_addrs(
                "callback_url",
                "evil.example.com",
                &rebind_addrs,
                https_only
            )
            .is_err()
        );

        let v6_rebind = [SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
            443,
        )];
        assert!(
            validate_resolved_addrs("callback_url", "evil.example.com", &v6_rebind, https_only)
                .is_err()
        );

        let v6_site_local_rebind = [SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 1)),
            443,
        )];
        assert!(
            validate_resolved_addrs(
                "callback_url",
                "evil.example.com",
                &v6_site_local_rebind,
                https_only
            )
            .is_err(),
            "DNS resolution to deprecated IPv6 site-local fec0::/10 MUST be blocked"
        );

        let public_addrs = [SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
        )];
        assert!(
            validate_resolved_addrs("callback_url", "example.com", &public_addrs, https_only)
                .is_ok()
        );
    }
}
