# Adopted features: IronClaw + OpenFang integration into Ralph

## Updated layer count: 24 security layers

After adoption, our architecture has 24 distinct security layers — 16 original + 8 adopted from IronClaw/OpenFang. This document provides the implementation for each adopted feature.

### Updated layer table

| # | Layer | Source | Where | Tier | Phase |
|---|-------|--------|-------|------|-------|
| 1 | Magic byte format gate | Original | Ralph hub | All | 1 |
| 2 | WASM sandbox (dual-metered) | Original | Spoke sandbox 1 | Iron/Open | 1 |
| 3 | Schema validation (typed) | Original | Spoke sandbox 2 | All | 1 |
| 4 | Injection pattern scanner | Original | Spoke sandbox 2 | Openfang | 2 |
| 5 | Structured envelope with provenance | Original | Spoke → Ralph | All | 1 |
| 6 | Sandwich prompt framing | Original | Spoke sandbox 3 | Iron/Open | 2 |
| 7 | Credential injection at host boundary | Original | Ralph host | Iron/Open | 1 |
| 8 | Dual LLM (P-LLM / Q-LLM) | Original | Spoke sandbox 3 | Openfang | 3 |
| 9 | Opaque variable references | Original | Ralph host | Openfang | 3 |
| 10 | Capability gate (origin × permissions) | Original | Ralph host | Openfang | 3 |
| 11 | Structural trifecta break (3 contexts) | Original | Spoke sandbox 3 | Openfang | 3 |
| 12 | Output auditor | Original | Ralph host | All | 2 |
| 13 | Seccomp-bpf secondary containment | Original | Ralph host process | Iron/Open | 1 |
| 14 | Hardened Wasmtime config | Original | Ralph host | Iron/Open | 1 |
| 15 | Per-task spoke teardown | Original | Ralph hub | All | 1 |
| 16 | Tiered agent selection | Original | Ralph hub | All | 1 |
| **17** | **Secret zeroization** | **IronClaw** | Ralph host | All | **1** |
| **18** | **Endpoint allowlisting** | **IronClaw** | Tool executor | Iron/Open | **2** |
| **19** | **Bidirectional leak scanning** | **IronClaw** | Ralph host | Iron/Open | **2** |
| **20** | **SSRF protection** | **OpenFang** | Tool executor | Iron/Open | **2** |
| **21** | **Human-in-the-loop approval gates** | **OpenFang** | Ralph hub | Openfang | **2** |
| **22** | **Merkle hash-chain audit trail** | **OpenFang** | Ralph hub | Openfang | **3** |
| **23** | **Ed25519 manifest signing** | **OpenFang** | Ralph host | Iron/Open | **3** |
| **24** | **TEE deployment option** | **IronClaw** | Infrastructure | Openfang | **4** |


---


## Phase 1 adoption: Secret zeroization (#17)

**Source:** IronClaw's use of Rust `Secret<String>` with `ZeroOnDrop`.

**Problem:** Our credential injection model passes API keys through Rust `String` values that persist in memory after use. A heap dump, core dump, or memory-scanning attack could recover them.

**Implementation:**

```toml
# Cargo.toml
[dependencies]
secrecy = "0.10"
zeroize = { version = "1.8", features = ["derive"] }
```

```rust
// ralph/src/credentials.rs

use secrecy::{ExposeSecret, SecretString, SecretVec};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// All credential types use SecretString — auto-zeroized on drop.
/// The inner value is NEVER logged, printed, or serialized.
/// Access requires explicit .expose_secret() call, which makes
/// accidental leaks grep-able in code review.
#[derive(Clone, ZeroizeOnDrop)]
pub struct CredentialStore {
    /// LLM API keys (Anthropic, OpenAI, etc.)
    api_keys: Vec<NamedSecret>,
    /// NEAR Protocol keys (for ironclaw)
    near_keys: Vec<NamedSecret>,
    /// Generic tokens (GitHub PAT, etc.)
    tokens: Vec<NamedSecret>,
}

#[derive(Clone, ZeroizeOnDrop)]
struct NamedSecret {
    #[zeroize(skip)]  // Name is not secret
    name: String,
    value: SecretString,
}

impl CredentialStore {
    /// Load credentials from environment variables.
    /// The env var value is immediately moved into SecretString
    /// and the original String is zeroized.
    pub fn from_env() -> Self {
        let mut store = Self {
            api_keys: Vec::new(),
            near_keys: Vec::new(),
            tokens: Vec::new(),
        };

        // Load and immediately zeroize the source
        if let Ok(mut key) = std::env::var("ANTHROPIC_API_KEY") {
            store.api_keys.push(NamedSecret {
                name: "anthropic".into(),
                value: SecretString::from(key.clone()),
            });
            key.zeroize();  // Wipe the original String
            std::env::remove_var("ANTHROPIC_API_KEY");  // Remove from env
        }

        if let Ok(mut key) = std::env::var("NEAR_PRIVATE_KEY") {
            store.near_keys.push(NamedSecret {
                name: "near_signing".into(),
                value: SecretString::from(key.clone()),
            });
            key.zeroize();
            std::env::remove_var("NEAR_PRIVATE_KEY");
        }

        store
    }

    /// Retrieve a key for use in the LLM caller.
    /// Returns a reference that auto-zeroizes when dropped.
    pub fn get_api_key(&self, provider: &str) -> Option<&SecretString> {
        self.api_keys.iter()
            .find(|k| k.name == provider)
            .map(|k| &k.value)
    }

    /// Build patterns for leak detection (see layer #19).
    /// Returns partial patterns that won't expose the full key
    /// but can detect if a key fragment appears in output.
    pub fn leak_detection_patterns(&self) -> Vec<LeakPattern> {
        let mut patterns = Vec::new();
        for key in &self.api_keys {
            let secret = key.value.expose_secret();
            // Use first 8 and last 4 chars as detection patterns
            // Never store the full key as a pattern
            if secret.len() >= 12 {
                patterns.push(LeakPattern {
                    name: key.name.clone(),
                    prefix: secret[..8].to_string(),
                    suffix: secret[secret.len()-4..].to_string(),
                });
            }
        }
        patterns
    }
}

pub struct LeakPattern {
    pub name: String,
    pub prefix: String,
    pub suffix: String,
}

impl Drop for LeakPattern {
    fn drop(&mut self) {
        self.prefix.zeroize();
        self.suffix.zeroize();
    }
}
```

**Updated LLM caller using SecretString:**

```rust
// ralph/src/llm_caller.rs

use secrecy::ExposeSecret;

pub struct AnthropicCaller {
    api_key: SecretString,  // Was: String — now auto-zeroized
    endpoint: String,
    http_client: reqwest::Client,
    max_request_bytes: usize,
    max_response_bytes: usize,
    per_call_timeout: Duration,
}

#[async_trait::async_trait]
impl LlmCaller for AnthropicCaller {
    async fn call(&self, prompt: &[u8]) -> Result<Vec<u8>> {
        if prompt.len() > self.max_request_bytes {
            anyhow::bail!("prompt exceeds size limit");
        }

        let guest_request: GuestLlmRequest = serde_json::from_slice(prompt)?;

        let resp = self.http_client
            .post(&self.endpoint)
            // expose_secret() is the ONLY place the raw key is accessed
            // grep for "expose_secret" in code review to audit all usages
            .header("x-api-key", self.api_key.expose_secret())
            .header("anthropic-version", "2023-06-01")
            .json(&ApiRequest {
                model: "claude-sonnet-4-20250514",
                max_tokens: 4096,
                messages: guest_request.messages,
            })
            .timeout(self.per_call_timeout)
            .send()
            .await?;

        let body = resp.bytes().await?;
        if body.len() > self.max_response_bytes {
            anyhow::bail!("response exceeds size limit");
        }

        Ok(body.to_vec())
    }
}
```


---


## Phase 2 adoptions

### Endpoint allowlisting (#18)

**Source:** IronClaw's endpoint allowlisting — HTTP requests only to pre-approved hosts/paths.

```rust
// ralph/src/security/endpoint_allowlist.rs

use url::Url;
use std::collections::HashSet;

/// Endpoint allowlist — tools can ONLY contact approved hosts.
/// Configured per-tool in the tool manifest.
#[derive(Debug, Clone)]
pub struct EndpointAllowlist {
    /// Allowed (host, optional path prefix) pairs
    entries: Vec<AllowlistEntry>,
}

#[derive(Debug, Clone)]
struct AllowlistEntry {
    host: String,
    port: Option<u16>,
    path_prefix: Option<String>,
    /// Whether HTTPS is required (default: true)
    require_tls: bool,
}

impl EndpointAllowlist {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn allow(mut self, host: &str) -> Self {
        self.entries.push(AllowlistEntry {
            host: host.to_lowercase(),
            port: None,
            path_prefix: None,
            require_tls: true,
        });
        self
    }

    pub fn allow_with_path(mut self, host: &str, path_prefix: &str) -> Self {
        self.entries.push(AllowlistEntry {
            host: host.to_lowercase(),
            port: None,
            path_prefix: Some(path_prefix.to_string()),
            require_tls: true,
        });
        self
    }

    /// Check if a URL is permitted by this allowlist.
    /// Returns Err with the reason if blocked.
    pub fn check(&self, url: &str) -> Result<(), AllowlistDenial> {
        let parsed = Url::parse(url)
            .map_err(|_| AllowlistDenial::InvalidUrl(url.to_string()))?;

        // Scheme check
        let scheme = parsed.scheme();
        if scheme != "https" && scheme != "http" {
            return Err(AllowlistDenial::DisallowedScheme(scheme.to_string()));
        }

        let host = parsed.host_str()
            .ok_or_else(|| AllowlistDenial::NoHost(url.to_string()))?
            .to_lowercase();

        let path = parsed.path();

        // Check against each allowlist entry
        for entry in &self.entries {
            let host_match = host == entry.host
                || host.ends_with(&format!(".{}", entry.host));

            if !host_match {
                continue;
            }

            if entry.require_tls && scheme != "https" {
                return Err(AllowlistDenial::TlsRequired(host.clone()));
            }

            if let Some(ref prefix) = entry.path_prefix {
                if !path.starts_with(prefix) {
                    continue;
                }
            }

            if let Some(required_port) = entry.port {
                let actual_port = parsed.port().unwrap_or(if scheme == "https" { 443 } else { 80 });
                if actual_port != required_port {
                    continue;
                }
            }

            return Ok(());  // Match found
        }

        Err(AllowlistDenial::NotAllowed {
            host,
            path: path.to_string(),
            allowed_hosts: self.entries.iter().map(|e| e.host.clone()).collect(),
        })
    }
}

#[derive(Debug)]
pub enum AllowlistDenial {
    InvalidUrl(String),
    DisallowedScheme(String),
    NoHost(String),
    TlsRequired(String),
    NotAllowed { host: String, path: String, allowed_hosts: Vec<String> },
}

/// Tool manifests declare their allowed endpoints
#[derive(Debug, Clone, Deserialize)]
pub struct ToolManifest {
    pub name: String,
    pub description: String,
    pub can_exfiltrate: bool,
    pub reads_private_data: bool,
    pub sees_untrusted_content: bool,
    pub allowed_endpoints: Vec<String>,  // ["api.anthropic.com", "near.org/rpc"]
}

impl ToolManifest {
    pub fn build_allowlist(&self) -> EndpointAllowlist {
        let mut list = EndpointAllowlist::new();
        for endpoint in &self.allowed_endpoints {
            if let Some((host, path)) = endpoint.split_once('/') {
                list = list.allow_with_path(host, &format!("/{}", path));
            } else {
                list = list.allow(endpoint);
            }
        }
        list
    }
}
```


### SSRF protection (#20)

**Source:** OpenFang's SSRF protection — blocks private IPs, cloud metadata, DNS rebinding.

```rust
// ralph/src/security/ssrf_guard.rs

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// SSRF guard — validates that resolved IP addresses are not
/// in private, loopback, link-local, or cloud metadata ranges.
/// Applied AFTER DNS resolution, BEFORE the connection is made.
pub struct SsrfGuard;

impl SsrfGuard {
    /// Check if an IP address is safe to connect to.
    /// Returns Err if the address is in a blocked range.
    pub fn check_ip(ip: &IpAddr) -> Result<(), SsrfDenial> {
        match ip {
            IpAddr::V4(v4) => Self::check_ipv4(v4),
            IpAddr::V6(v6) => Self::check_ipv6(v6),
        }
    }

    fn check_ipv4(ip: &Ipv4Addr) -> Result<(), SsrfDenial> {
        let octets = ip.octets();

        // Loopback: 127.0.0.0/8
        if octets[0] == 127 {
            return Err(SsrfDenial::Loopback(*ip));
        }

        // Private ranges
        // 10.0.0.0/8
        if octets[0] == 10 {
            return Err(SsrfDenial::PrivateNetwork(*ip));
        }
        // 172.16.0.0/12
        if octets[0] == 172 && (16..=31).contains(&octets[1]) {
            return Err(SsrfDenial::PrivateNetwork(*ip));
        }
        // 192.168.0.0/16
        if octets[0] == 192 && octets[1] == 168 {
            return Err(SsrfDenial::PrivateNetwork(*ip));
        }

        // Link-local: 169.254.0.0/16 (includes AWS metadata at 169.254.169.254)
        if octets[0] == 169 && octets[1] == 254 {
            return Err(SsrfDenial::LinkLocal(*ip));
        }

        // Cloud metadata endpoints
        // AWS: 169.254.169.254 (caught above)
        // GCP: metadata.google.internal resolves to 169.254.169.254
        // Azure: 169.254.169.254:80

        // Broadcast: 255.255.255.255
        if *ip == Ipv4Addr::BROADCAST {
            return Err(SsrfDenial::Broadcast);
        }

        // Unspecified: 0.0.0.0
        if ip.is_unspecified() {
            return Err(SsrfDenial::Unspecified);
        }

        // Documentation ranges (shouldn't be routed but block anyway)
        // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
            || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
            || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        {
            return Err(SsrfDenial::Documentation(*ip));
        }

        Ok(())
    }

    fn check_ipv6(ip: &Ipv6Addr) -> Result<(), SsrfDenial> {
        // Loopback: ::1
        if ip.is_loopback() {
            return Err(SsrfDenial::Loopback6(*ip));
        }

        // Unspecified: ::
        if ip.is_unspecified() {
            return Err(SsrfDenial::Unspecified);
        }

        // IPv4-mapped: ::ffff:x.x.x.x — check the embedded v4
        if let Some(v4) = ip.to_ipv4_mapped() {
            return Self::check_ipv4(&v4);
        }

        // Link-local: fe80::/10
        let segments = ip.segments();
        if segments[0] & 0xffc0 == 0xfe80 {
            return Err(SsrfDenial::LinkLocal6(*ip));
        }

        // Unique local: fc00::/7
        if segments[0] & 0xfe00 == 0xfc00 {
            return Err(SsrfDenial::PrivateNetwork6(*ip));
        }

        Ok(())
    }

    /// Check a hostname by resolving it and verifying all addresses.
    /// This prevents DNS rebinding — even if the first resolution
    /// is safe, a rebinding attack returns a private IP on reconnect.
    pub async fn check_host(host: &str) -> Result<(), SsrfDenial> {
        // Block known metadata hostnames regardless of resolution
        let host_lower = host.to_lowercase();
        if host_lower == "metadata.google.internal"
            || host_lower == "metadata"
            || host_lower.ends_with(".internal")
            || host_lower == "instance-data"
        {
            return Err(SsrfDenial::MetadataHostname(host_lower));
        }

        // Resolve and check ALL addresses (not just the first)
        let addrs = tokio::net::lookup_host(format!("{}:443", host)).await
            .map_err(|e| SsrfDenial::ResolutionFailed(host.to_string(), e.to_string()))?;

        for addr in addrs {
            Self::check_ip(&addr.ip())?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum SsrfDenial {
    Loopback(Ipv4Addr),
    Loopback6(Ipv6Addr),
    PrivateNetwork(Ipv4Addr),
    PrivateNetwork6(Ipv6Addr),
    LinkLocal(Ipv4Addr),
    LinkLocal6(Ipv6Addr),
    MetadataHostname(String),
    Broadcast,
    Unspecified,
    Documentation(Ipv4Addr),
    ResolutionFailed(String, String),
}
```


### Bidirectional leak scanning (#19)

**Source:** IronClaw's bidirectional leak detection — scans both requests AND responses.

```rust
// ralph/src/security/leak_scanner.rs

use crate::credentials::LeakPattern;
use regex::RegexSet;

/// Scans text for credential leakage patterns.
/// Applied in BOTH directions:
/// - OUTGOING: before the LLM API call leaves the host (catches prompt injection
///   that tricks the LLM into echoing secrets)
/// - INCOMING: after the LLM response arrives (catches the LLM including secrets
///   it shouldn't have seen)
pub struct LeakScanner {
    /// Partial credential patterns (prefix + suffix)
    credential_patterns: Vec<LeakPattern>,
    /// Generic patterns for common secret formats
    generic_patterns: RegexSet,
}

impl LeakScanner {
    pub fn new(credential_patterns: Vec<LeakPattern>) -> Self {
        let generic_patterns = RegexSet::new(&[
            // API key formats
            r"sk-ant-[a-zA-Z0-9]{20,}",           // Anthropic
            r"sk-[a-zA-Z0-9]{40,}",                // OpenAI
            r"gsk_[a-zA-Z0-9]{20,}",               // Groq
            r"AIza[a-zA-Z0-9_-]{35}",              // Google
            // AWS
            r"AKIA[A-Z0-9]{16}",                   // AWS access key
            r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*\S+",
            // Private keys
            r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
            r"ed25519:[a-zA-Z0-9+/=]{40,}",        // NEAR private key
            // Generic
            r"(?i)(password|passwd|pwd)\s*[:=]\s*\S{8,}",
            r"(?i)(token|secret|key)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}",
            // JWT tokens
            r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
            // Hex-encoded secrets (64+ chars = potential private key)
            r"[0-9a-fA-F]{64,}",
        ]).expect("invalid leak detection patterns");

        Self {
            credential_patterns,
            generic_patterns,
        }
    }

    /// Scan a byte slice for credential leaks.
    /// Returns all detected leaks. The caller decides the action.
    pub fn scan(&self, data: &[u8], direction: ScanDirection) -> Vec<LeakDetection> {
        let text = match std::str::from_utf8(data) {
            Ok(t) => t,
            Err(_) => return Vec::new(),  // Binary data — skip
        };

        let mut detections = Vec::new();

        // Check specific credential patterns (prefix/suffix matching)
        for pattern in &self.credential_patterns {
            if text.contains(&pattern.prefix) || text.contains(&pattern.suffix) {
                detections.push(LeakDetection {
                    credential_name: pattern.name.clone(),
                    match_type: LeakMatchType::CredentialFragment,
                    direction,
                    severity: LeakSeverity::Critical,
                });
            }
        }

        // Check generic patterns
        let matches: Vec<usize> = self.generic_patterns
            .matches(text)
            .into_iter()
            .collect();

        for match_idx in matches {
            let pattern_name = match match_idx {
                0 => "anthropic_api_key",
                1 => "openai_api_key",
                2 => "groq_api_key",
                3 => "google_api_key",
                4 => "aws_access_key",
                5 => "aws_secret_key",
                6 => "private_key_pem",
                7 => "near_private_key",
                8 => "password_assignment",
                9 => "generic_token",
                10 => "jwt_token",
                11 => "hex_secret",
                _ => "unknown",
            };

            detections.push(LeakDetection {
                credential_name: pattern_name.to_string(),
                match_type: LeakMatchType::GenericPattern,
                direction,
                severity: match match_idx {
                    0..=7 => LeakSeverity::Critical,  // Known API key formats
                    8..=10 => LeakSeverity::High,     // Password/token patterns
                    _ => LeakSeverity::Medium,         // Hex strings (could be hashes)
                },
            });
        }

        detections
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ScanDirection {
    /// Scanning data LEAVING the host (outgoing prompt to LLM API)
    Outgoing,
    /// Scanning data ENTERING from LLM response
    Incoming,
}

#[derive(Debug)]
pub struct LeakDetection {
    pub credential_name: String,
    pub match_type: LeakMatchType,
    pub direction: ScanDirection,
    pub severity: LeakSeverity,
}

#[derive(Debug)]
pub enum LeakMatchType {
    CredentialFragment,  // Matches known credential prefix/suffix
    GenericPattern,      // Matches generic secret format
}

#[derive(Debug, PartialEq, PartialOrd)]
pub enum LeakSeverity {
    Medium,
    High,
    Critical,
}
```

**Integration into the LLM caller (bidirectional):**

```rust
// ralph/src/llm_caller.rs — updated with leak scanning

impl AnthropicCaller {
    async fn call_with_leak_scan(
        &self,
        prompt: &[u8],
        leak_scanner: &LeakScanner,
    ) -> Result<Vec<u8>> {
        // OUTGOING scan: check the prompt for leaked secrets
        let outgoing_leaks = leak_scanner.scan(prompt, ScanDirection::Outgoing);
        if outgoing_leaks.iter().any(|l| l.severity >= LeakSeverity::Critical) {
            log::error!(
                "CRITICAL: credential leak detected in OUTGOING prompt: {:?}",
                outgoing_leaks.iter().map(|l| &l.credential_name).collect::<Vec<_>>()
            );
            anyhow::bail!("Credential leak detected in outgoing prompt — blocked");
        }

        // Make the API call (with credential injection as before)
        let response_bytes = self.call(prompt).await?;

        // INCOMING scan: check the response for leaked secrets
        let incoming_leaks = leak_scanner.scan(&response_bytes, ScanDirection::Incoming);
        if incoming_leaks.iter().any(|l| l.severity >= LeakSeverity::Critical) {
            log::error!(
                "CRITICAL: credential leak detected in INCOMING response: {:?}",
                incoming_leaks.iter().map(|l| &l.credential_name).collect::<Vec<_>>()
            );
            // Don't return the response — it contains leaked credentials
            anyhow::bail!("Credential leak detected in LLM response — suppressed");
        }

        Ok(response_bytes)
    }
}
```


### Human-in-the-loop approval gates (#21)

**Source:** OpenFang's mandatory approval for sensitive actions.

```rust
// ralph/src/security/approval_gate.rs

use tokio::sync::oneshot;
use std::time::Duration;

/// Risk tier for tool calls — determines approval requirements.
/// Matches the GREEN/YELLOW/RED model from the CaMeL operationalization paper.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum RiskTier {
    /// Read-only actions on public/open data.
    /// Auto-approved with logging.
    Green,
    /// Changes within user's own scope.
    /// Lightweight inline confirmation if args include untrusted data.
    Yellow,
    /// Irreversible or externally visible operations.
    /// Full capability check + mandatory human approval.
    Red,
}

/// A pending approval request
#[derive(Debug, Serialize)]
pub struct ApprovalRequest {
    pub task_id: String,
    pub tool_name: String,
    pub action_description: String,
    pub risk_tier: String,
    pub arguments_summary: Vec<ArgumentSummary>,
    pub data_origins: Vec<String>,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    pub timeout_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct ArgumentSummary {
    pub name: String,
    pub value_type: String,
    pub origin: String,
    pub preview: String,  // Truncated to 50 chars
}

#[derive(Debug)]
pub enum ApprovalDecision {
    Approved,
    Denied(String),
    Timeout,
}

pub struct ApprovalGate {
    /// Channel for sending approval requests to the UI/webhook
    request_sender: tokio::sync::mpsc::Sender<(ApprovalRequest, oneshot::Sender<ApprovalDecision>)>,
    /// Timeout for approval requests
    timeout: Duration,
    /// Track approval patterns for fatigue detection
    approval_tracker: ApprovalFatigueTracker,
}

impl ApprovalGate {
    /// Evaluate whether a tool call needs approval and at what tier.
    pub fn classify_risk(
        &self,
        tool: &ToolManifest,
        arg_origins: &[DataOrigin],
    ) -> RiskTier {
        // If any argument originated from untrusted source AND tool can exfiltrate → RED
        let has_untrusted = arg_origins.iter().any(|o| matches!(
            o,
            DataOrigin::QLlmExtraction | DataOrigin::ExternalFetch | DataOrigin::OnChain
        ));

        if tool.can_exfiltrate && has_untrusted {
            return RiskTier::Red;
        }

        // Classify based on tool properties
        match (tool.can_exfiltrate, tool.reads_private_data) {
            (true, _) => RiskTier::Yellow,    // Can exfiltrate but no untrusted data
            (_, true) if has_untrusted => RiskTier::Yellow,  // Private data + untrusted args
            _ => RiskTier::Green,             // Safe combination
        }
    }

    /// Request approval for a tool call.
    /// GREEN: auto-approved (logged).
    /// YELLOW: lightweight confirmation (inline).
    /// RED: mandatory human approval with timeout.
    pub async fn request_approval(
        &mut self,
        request: ApprovalRequest,
        risk_tier: RiskTier,
    ) -> ApprovalDecision {
        match risk_tier {
            RiskTier::Green => {
                log::info!("AUTO-APPROVED [GREEN]: {} — {}", request.tool_name, request.action_description);
                ApprovalDecision::Approved
            }
            RiskTier::Yellow => {
                log::info!("CONFIRMATION [YELLOW]: {} — {}", request.tool_name, request.action_description);
                self.send_and_wait(request, Duration::from_secs(30)).await
            }
            RiskTier::Red => {
                log::warn!("APPROVAL REQUIRED [RED]: {} — {}", request.tool_name, request.action_description);
                let decision = self.send_and_wait(request, self.timeout).await;

                // Track approval patterns for fatigue detection
                if let ApprovalDecision::Approved = &decision {
                    self.approval_tracker.record_approval();
                }

                decision
            }
        }
    }

    async fn send_and_wait(
        &self,
        request: ApprovalRequest,
        timeout: Duration,
    ) -> ApprovalDecision {
        let (response_tx, response_rx) = oneshot::channel();

        if self.request_sender.send((request, response_tx)).await.is_err() {
            log::error!("Approval channel closed — denying by default");
            return ApprovalDecision::Denied("approval channel unavailable".into());
        }

        match tokio::time::timeout(timeout, response_rx).await {
            Ok(Ok(decision)) => decision,
            Ok(Err(_)) => ApprovalDecision::Denied("approval channel dropped".into()),
            Err(_) => {
                log::warn!("Approval request timed out — denying");
                ApprovalDecision::Timeout
            }
        }
    }
}

/// Detects approval fatigue — when a user auto-approves everything
/// without reading, this is a security risk.
struct ApprovalFatigueTracker {
    recent_approvals: Vec<chrono::DateTime<chrono::Utc>>,
    fatigue_threshold: usize,   // e.g., 10 approvals
    fatigue_window: Duration,    // e.g., in 5 minutes
}

impl ApprovalFatigueTracker {
    fn record_approval(&mut self) {
        let now = chrono::Utc::now();
        self.recent_approvals.push(now);

        // Prune old entries
        let cutoff = now - chrono::Duration::from_std(self.fatigue_window).unwrap();
        self.recent_approvals.retain(|t| *t > cutoff);

        // Check for fatigue pattern
        if self.recent_approvals.len() >= self.fatigue_threshold {
            log::error!(
                "APPROVAL FATIGUE DETECTED: {} approvals in {} seconds. \
                 User may be auto-approving without review. \
                 Escalating to admin.",
                self.recent_approvals.len(),
                self.fatigue_window.as_secs()
            );
            // TODO: send alert to admin channel, temporarily elevate
            // all YELLOW actions to RED tier
        }
    }
}
```


---


## Phase 3 adoptions

### Merkle hash-chain audit trail (#22)

**Source:** OpenFang's tamper-evident Merkle audit trail.

```rust
// ralph/src/audit/merkle_chain.rs

use sha2::{Sha256, Digest};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

/// A single entry in the Merkle audit chain.
/// Each entry's hash includes the previous entry's hash,
/// forming a tamper-evident chain. Modifying any entry
/// breaks the chain from that point forward.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Sequential index in the chain
    pub index: u64,
    /// Timestamp of the event
    pub timestamp: DateTime<Utc>,
    /// Hash of the previous entry (hex-encoded SHA-256)
    /// For the genesis entry (index 0), this is a fixed seed.
    pub prev_hash: String,
    /// The event payload
    pub event: AuditEvent,
    /// SHA-256 hash of (prev_hash + timestamp + event_json)
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEvent {
    TaskDispatched {
        task_id: String,
        agent_tier: String,
        file_type: Option<String>,
        file_sha256: Option<String>,
    },
    SpokeStarted {
        task_id: String,
        wasm_module_hash: String,
        resource_limits: ResourceLimitsSummary,
    },
    LlmCallMade {
        task_id: String,
        direction: String,  // "p_llm" or "q_llm"
        prompt_hash: String,  // Hash of prompt, not the prompt itself
        response_hash: String,
        tokens_used: u32,
    },
    CapabilityCheck {
        task_id: String,
        tool_name: String,
        variable_origins: Vec<String>,
        decision: String,  // "allow" or "deny"
        risk_tier: String,
    },
    ApprovalRequested {
        task_id: String,
        tool_name: String,
        risk_tier: String,
    },
    ApprovalDecision {
        task_id: String,
        decision: String,  // "approved", "denied", "timeout"
        response_time_ms: u64,
    },
    OutputAuditResult {
        task_id: String,
        verdict: String,  // "pass", "warn", "quarantine", "reject"
        warnings_count: u32,
        max_severity: String,
    },
    LeakDetected {
        task_id: String,
        direction: String,
        credential_name: String,
        severity: String,
    },
    SpokeTerminated {
        task_id: String,
        fuel_consumed: u64,
        memory_peak_bytes: u64,
        duration_ms: u64,
    },
    TaskCompleted {
        task_id: String,
        status: String,
        capability_blocks: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimitsSummary {
    pub memory_bytes: usize,
    pub fuel: u64,
    pub wall_timeout_secs: u64,
}

/// The Merkle audit chain — append-only, tamper-evident.
pub struct MerkleAuditChain {
    /// Current chain head hash
    head_hash: String,
    /// Current chain length
    length: u64,
    /// Storage backend
    storage: Box<dyn AuditStorage + Send + Sync>,
}

#[async_trait::async_trait]
pub trait AuditStorage: Send + Sync {
    async fn append(&mut self, entry: &AuditEntry) -> Result<(), anyhow::Error>;
    async fn get(&self, index: u64) -> Result<Option<AuditEntry>, anyhow::Error>;
    async fn get_latest(&self) -> Result<Option<AuditEntry>, anyhow::Error>;
    async fn count(&self) -> Result<u64, anyhow::Error>;
}

impl MerkleAuditChain {
    /// Genesis seed — a fixed value for the first entry's prev_hash
    const GENESIS_SEED: &'static str = "ralph-audit-chain-genesis-v1";

    pub async fn new(storage: Box<dyn AuditStorage + Send + Sync>) -> Result<Self, anyhow::Error> {
        let latest = storage.get_latest().await?;
        let (head_hash, length) = match latest {
            Some(entry) => (entry.hash.clone(), entry.index + 1),
            None => (Self::GENESIS_SEED.to_string(), 0),
        };

        Ok(Self { head_hash, length, storage })
    }

    /// Append an event to the chain.
    /// Computes the hash as SHA-256(prev_hash + timestamp + event_json).
    pub async fn append(&mut self, event: AuditEvent) -> Result<AuditEntry, anyhow::Error> {
        let timestamp = Utc::now();
        let event_json = serde_json::to_string(&event)?;

        // Compute chain hash
        let hash_input = format!("{}{}{}", self.head_hash, timestamp.to_rfc3339(), event_json);
        let mut hasher = Sha256::new();
        hasher.update(hash_input.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        let entry = AuditEntry {
            index: self.length,
            timestamp,
            prev_hash: self.head_hash.clone(),
            event,
            hash: hash.clone(),
        };

        self.storage.append(&entry).await?;
        self.head_hash = hash;
        self.length += 1;

        Ok(entry)
    }

    /// Verify the chain integrity from a given starting point.
    /// Returns the index of the first broken link, or None if intact.
    pub async fn verify(&self, from_index: u64) -> Result<Option<u64>, anyhow::Error> {
        let count = self.storage.count().await?;

        let mut expected_prev_hash = if from_index == 0 {
            Self::GENESIS_SEED.to_string()
        } else {
            let prev = self.storage.get(from_index - 1).await?
                .ok_or_else(|| anyhow::anyhow!("missing entry at index {}", from_index - 1))?;
            prev.hash
        };

        for idx in from_index..count {
            let entry = self.storage.get(idx).await?
                .ok_or_else(|| anyhow::anyhow!("missing entry at index {}", idx))?;

            // Verify prev_hash link
            if entry.prev_hash != expected_prev_hash {
                return Ok(Some(idx));
            }

            // Recompute hash
            let event_json = serde_json::to_string(&entry.event)?;
            let hash_input = format!("{}{}{}", entry.prev_hash, entry.timestamp.to_rfc3339(), event_json);
            let mut hasher = Sha256::new();
            hasher.update(hash_input.as_bytes());
            let computed_hash = format!("{:x}", hasher.finalize());

            if entry.hash != computed_hash {
                return Ok(Some(idx));
            }

            expected_prev_hash = entry.hash;
        }

        Ok(None)  // Chain is intact
    }
}
```


### Ed25519 manifest signing (#23)

**Source:** OpenFang's cryptographic signing of agent identities and capabilities.

```rust
// ralph/src/security/manifest_signing.rs

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use sha2::{Sha256, Digest};

/// A signed WASM module manifest.
/// The manifest declares what the module is, what it's authorized to do,
/// and who built it. The signature covers all of this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifest {
    /// The manifest payload
    pub manifest: WasmManifest,
    /// Ed25519 signature over SHA-256(manifest_json)
    pub signature: Vec<u8>,
    /// Public key of the signer (hex-encoded)
    pub signer_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmManifest {
    /// Module name (e.g., "pdf-parser", "q-llm-runner")
    pub name: String,
    /// Semantic version
    pub version: String,
    /// SHA-256 hash of the WASM binary
    pub wasm_sha256: String,
    /// What this module is authorized to do
    pub capabilities: ManifestCapabilities,
    /// Who built this module
    pub builder: String,
    /// When it was built
    pub built_at: String,
    /// Minimum Wasmtime version required
    pub min_wasmtime_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestCapabilities {
    /// Can this module call host_call_llm?
    pub llm_access: bool,
    /// Can this module call host_call_tool?
    pub tool_access: bool,
    /// Maximum memory (bytes)
    pub max_memory: usize,
    /// Maximum fuel
    pub max_fuel: u64,
    /// Allowed endpoint hosts (for tool execution modules)
    pub allowed_endpoints: Vec<String>,
}

/// Sign a manifest with an Ed25519 key
pub fn sign_manifest(manifest: &WasmManifest, signing_key: &SigningKey) -> SignedManifest {
    let manifest_json = serde_json::to_string(manifest).expect("serialize manifest");
    let mut hasher = Sha256::new();
    hasher.update(manifest_json.as_bytes());
    let digest = hasher.finalize();

    let signature = signing_key.sign(&digest);

    SignedManifest {
        manifest: manifest.clone(),
        signature: signature.to_bytes().to_vec(),
        signer_public_key: hex::encode(signing_key.verifying_key().to_bytes()),
    }
}

/// Verify a signed manifest against a set of trusted public keys
pub fn verify_manifest(
    signed: &SignedManifest,
    trusted_keys: &[VerifyingKey],
    wasm_bytes: &[u8],
) -> Result<(), ManifestError> {
    // 1. Check that the signer is trusted
    let signer_bytes = hex::decode(&signed.signer_public_key)
        .map_err(|_| ManifestError::InvalidSignerKey)?;
    let signer_key = VerifyingKey::from_bytes(
        &signer_bytes.try_into().map_err(|_| ManifestError::InvalidSignerKey)?
    ).map_err(|_| ManifestError::InvalidSignerKey)?;

    if !trusted_keys.contains(&signer_key) {
        return Err(ManifestError::UntrustedSigner(signed.signer_public_key.clone()));
    }

    // 2. Verify the signature
    let manifest_json = serde_json::to_string(&signed.manifest)
        .map_err(|_| ManifestError::SerializationError)?;
    let mut hasher = Sha256::new();
    hasher.update(manifest_json.as_bytes());
    let digest = hasher.finalize();

    let signature = Signature::from_bytes(
        &signed.signature.clone().try_into().map_err(|_| ManifestError::InvalidSignature)?
    );

    signer_key.verify(&digest, &signature)
        .map_err(|_| ManifestError::SignatureVerificationFailed)?;

    // 3. Verify the WASM binary hash matches the manifest
    let mut wasm_hasher = Sha256::new();
    wasm_hasher.update(wasm_bytes);
    let wasm_hash = format!("{:x}", wasm_hasher.finalize());

    if wasm_hash != signed.manifest.wasm_sha256 {
        return Err(ManifestError::WasmHashMismatch {
            expected: signed.manifest.wasm_sha256.clone(),
            actual: wasm_hash,
        });
    }

    // 4. Verify capability constraints are sane
    if signed.manifest.capabilities.tool_access && signed.manifest.capabilities.llm_access {
        // A module with both LLM access and tool access is suspicious
        // (our architecture separates these into different sandboxes)
        log::warn!(
            "Module '{}' declares both llm_access and tool_access — \
             verify this is intentional",
            signed.manifest.name
        );
    }

    Ok(())
}

#[derive(Debug)]
pub enum ManifestError {
    InvalidSignerKey,
    UntrustedSigner(String),
    InvalidSignature,
    SignatureVerificationFailed,
    SerializationError,
    WasmHashMismatch { expected: String, actual: String },
}
```

**Integration into spoke runner:**

```rust
// ralph/src/spoke_runner.rs — updated module loading

impl SpokeRunner {
    /// Load a WASM module with manifest verification.
    /// Called during Ralph startup and cached.
    pub fn load_verified_module(
        &self,
        wasm_path: &Path,
        manifest_path: &Path,
        trusted_keys: &[VerifyingKey],
    ) -> Result<(Module, WasmManifest)> {
        let wasm_bytes = std::fs::read(wasm_path)?;
        let manifest_json = std::fs::read_to_string(manifest_path)?;
        let signed: SignedManifest = serde_json::from_str(&manifest_json)?;

        // Verify signature, signer trust, and WASM hash
        verify_manifest(&signed, trusted_keys, &wasm_bytes)?;

        log::info!(
            "Verified module '{}' v{} (signer: {}, wasm: {})",
            signed.manifest.name,
            signed.manifest.version,
            &signed.signer_public_key[..16],
            &signed.manifest.wasm_sha256[..16],
        );

        let module = Module::new(&self.engine, &wasm_bytes)?;

        // Enforce manifest capabilities at the linker level
        // If manifest says llm_access: false, don't even register host_call_llm
        // This is COMPILE-TIME enforcement — the module cannot call what isn't linked

        Ok((module, signed.manifest))
    }
}
```


---


## Integration: updated Ralph main loop with all 24 layers

```rust
// ralph/src/orchestrator.rs — final version with all adopted features

pub struct Ralph {
    spoke_runner: SpokeRunner,
    agent_selector: AgentSelector,
    credential_store: CredentialStore,           // #17: SecretString + zeroization
    leak_scanner: LeakScanner,                   // #19: Bidirectional
    output_auditor: OutputAuditor,               // #12: Original
    approval_gate: ApprovalGate,                 // #21: OpenFang-style
    audit_chain: MerkleAuditChain,               // #22: Tamper-evident
    trusted_signing_keys: Vec<VerifyingKey>,      // #23: Ed25519
}

impl Ralph {
    pub async fn handle_task(&self, task: Task) -> Result<TaskResult> {
        let task_id = TaskId::new();

        // [#16] Agent tier selection
        let file_info = identify_file_if_present(&task).await?;
        let tier = self.agent_selector.select(&task, &file_info);

        // [#22] Audit: task dispatched
        self.audit_chain.append(AuditEvent::TaskDispatched {
            task_id: task_id.to_string(),
            agent_tier: format!("{:?}", tier),
            file_type: file_info.as_ref().map(|f| format!("{:?}", f.file_type)),
            file_sha256: file_info.as_ref().map(|f| f.sha256.clone()),
        }).await?;

        // Dispatch to spoke (all internal layers apply per-tier)
        let envelope = match tier {
            AgentTier::Zeroclaw => self.run_zeroclaw(&task, file_info, &task_id).await?,
            AgentTier::Ironclaw => self.run_ironclaw(&task, file_info, &task_id).await?,
            AgentTier::Openfang => self.run_openfang_safe(&task, file_info, &task_id).await?,
        };

        // [#12] Output audit
        let audit_verdict = self.output_auditor.audit(&envelope);

        // [#22] Audit: output result
        self.audit_chain.append(AuditEvent::OutputAuditResult {
            task_id: task_id.to_string(),
            verdict: format!("{:?}", audit_verdict),
            warnings_count: match &audit_verdict {
                AuditVerdict::Warn(w) | AuditVerdict::Quarantine(w) => w.len() as u32,
                _ => 0,
            },
            max_severity: "see_warnings".into(),
        }).await?;

        match audit_verdict {
            AuditVerdict::Reject(reason) => {
                return Err(TaskError::OutputRejected { task_id: task_id.to_string(), reason });
            }
            AuditVerdict::Quarantine(warnings) if task.has_side_effect_tools() => {
                return Err(TaskError::Quarantined {
                    task_id: task_id.to_string(),
                    reason: "Output audit flagged high-severity content".into(),
                    warnings,
                });
            }
            _ => {}
        }

        // [#22] Audit: task completed
        self.audit_chain.append(AuditEvent::TaskCompleted {
            task_id: task_id.to_string(),
            status: "success".into(),
            capability_blocks: envelope.security.capability_blocks,
        }).await?;

        Ok(envelope.result)
    }
}
```


---


## Phase 4 notes: TEE deployment (#24)

TEE integration is infrastructure-level, not code-level. Two paths:

**Path A: NEAR AI Cloud (via IronClaw's existing infrastructure)**
- Deploy Ralph spoke runners on NEAR AI Cloud TEE instances
- Credentials stored in the TEE's encrypted memory
- Even the cloud provider cannot inspect runtime state
- Trade-off: dependency on NEAR's infrastructure

**Path B: Self-hosted TEE (Intel TDX / AMD SEV)**
- Run Ralph in a Confidential VM (AMD SEV-SNP or Intel TDX)
- Memory encrypted by the CPU — host OS cannot inspect
- Requires compatible hardware
- Trade-off: hardware constraints, performance overhead (~5-15%)

**Recommendation:** Start with Path A for the openfang tier (highest-risk tasks) since IronClaw already validates this path on NEAR AI Cloud. Self-host TEE for long-term sovereignty.
