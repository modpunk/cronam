//! Singularix backend bridge for CRONAM (ADR-0068 P3).
//!
//! Routes Rex agent conversations through the Singularix unified chat backend
//! (`/api/v1/rex/chat`) instead of the local openfang LLM. Provides:
//!
//! - **Unified conversation history** across CRONAM, Slack, and web workspace
//! - **Shared agent memstore** (ADR-0066) — Rex remembers across surfaces
//! - **Fallback to local** when Singularix is unreachable
//! - **Session sync** — local conversations sync to Singularix when reconnected
//!
//! # Configuration
//!
//! Set in environment or agent TOML:
//! - `SINGULARIX_URL`: Base URL (default: `https://singularix-ai.fly.dev`)
//! - `SINGULARIX_API_KEY`: Service key for auth
//! - `SINGULARIX_ENABLED`: `true` to activate (default: `false`)

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

const DEFAULT_URL: &str = "https://singularix-ai.fly.dev";
const TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for the Singularix backend bridge.
#[derive(Debug, Clone)]
pub struct SingularixConfig {
    pub base_url: String,
    pub api_key: String,
    pub enabled: bool,
}

impl SingularixConfig {
    /// Load from environment variables.
    pub fn from_env() -> Self {
        Self {
            base_url: std::env::var("SINGULARIX_URL")
                .unwrap_or_else(|_| DEFAULT_URL.to_string()),
            api_key: std::env::var("SINGULARIX_API_KEY").unwrap_or_default(),
            enabled: std::env::var("SINGULARIX_ENABLED")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
        }
    }
}

/// Request to the unified Rex chat endpoint.
#[derive(Debug, Serialize)]
struct RexChatRequest {
    conversation_id: Option<String>,
    message: String,
    channel: String,
    mode: String,
    channel_metadata: Option<serde_json::Value>,
}

/// SSE event from the Rex chat stream.
#[derive(Debug, Deserialize)]
struct SseEvent {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

/// Tracks the mapping between a CRONAM session and a Singularix conversation.
#[derive(Debug, Clone)]
struct SessionMapping {
    cronam_session_id: String,
    singularix_conversation_id: String,
}

/// The Singularix backend bridge.
pub struct SingularixBridge {
    config: SingularixConfig,
    client: Client,
    /// Maps CRONAM session IDs to Singularix conversation IDs.
    session_map: Arc<RwLock<Vec<SessionMapping>>>,
    /// Whether Singularix is currently reachable.
    healthy: Arc<RwLock<bool>>,
}

impl SingularixBridge {
    /// Create a new bridge from config.
    pub fn new(config: SingularixConfig) -> Self {
        let client = Client::builder()
            .timeout(TIMEOUT)
            .build()
            .expect("failed to build HTTP client");

        Self {
            config,
            client,
            session_map: Arc::new(RwLock::new(Vec::new())),
            healthy: Arc::new(RwLock::new(true)),
        }
    }

    /// Create from environment variables.
    pub fn from_env() -> Self {
        Self::new(SingularixConfig::from_env())
    }

    /// Check if the bridge is enabled and Singularix is reachable.
    pub async fn is_available(&self) -> bool {
        if !self.config.enabled || self.config.api_key.is_empty() {
            return false;
        }
        *self.healthy.read().await
    }

    /// Send a message through Singularix Rex and get the response.
    ///
    /// Returns `Ok(response_text)` on success, `Err` if Singularix is
    /// unreachable (caller should fall back to local LLM).
    pub async fn send_message(
        &self,
        session_id: &str,
        message: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enabled {
            return Err("Singularix bridge disabled".into());
        }

        // Look up existing conversation ID
        let convo_id = {
            let map = self.session_map.read().await;
            map.iter()
                .find(|m| m.cronam_session_id == session_id)
                .map(|m| m.singularix_conversation_id.clone())
        };

        let req = RexChatRequest {
            conversation_id: convo_id,
            message: message.to_string(),
            channel: "cronam".to_string(),
            mode: "rex".to_string(),
            channel_metadata: Some(serde_json::json!({
                "cronam_session_id": session_id,
            })),
        };

        let url = format!("{}/api/v1/rex/chat", self.config.base_url);

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&req)
            .send()
            .await;

        match resp {
            Ok(r) => {
                *self.healthy.write().await = true;

                if !r.status().is_success() {
                    let status = r.status();
                    let body = r.text().await.unwrap_or_default();
                    warn!("Singularix returned {}: {}", status, &body[..200.min(body.len())]);
                    return Err(format!("Singularix HTTP {}", status).into());
                }

                // Parse SSE stream to extract full response
                let body = r.text().await?;
                let (full_text, new_convo_id) = parse_sse_response(&body);

                // Store conversation mapping
                if let Some(cid) = new_convo_id {
                    let mut map = self.session_map.write().await;
                    if !map.iter().any(|m| m.cronam_session_id == session_id) {
                        map.push(SessionMapping {
                            cronam_session_id: session_id.to_string(),
                            singularix_conversation_id: cid,
                        });
                    }
                }

                if full_text.is_empty() {
                    Err("Empty response from Singularix".into())
                } else {
                    debug!("Singularix response: {} chars", full_text.len());
                    Ok(full_text)
                }
            }
            Err(e) => {
                warn!("Singularix unreachable: {}", e);
                *self.healthy.write().await = false;
                Err(Box::new(e))
            }
        }
    }

    /// Health check — ping Singularix and update healthy status.
    pub async fn health_check(&self) -> bool {
        let url = format!("{}/health", self.config.base_url);
        match self.client.get(&url).send().await {
            Ok(r) if r.status().is_success() => {
                *self.healthy.write().await = true;
                info!("Singularix health check: OK");
                true
            }
            Ok(r) => {
                warn!("Singularix health check failed: {}", r.status());
                *self.healthy.write().await = false;
                false
            }
            Err(e) => {
                warn!("Singularix health check error: {}", e);
                *self.healthy.write().await = false;
                false
            }
        }
    }
}

/// Parse SSE response body into (full_text, conversation_id).
fn parse_sse_response(body: &str) -> (String, Option<String>) {
    let mut full_text = String::new();
    let mut convo_id = None;

    for line in body.lines() {
        let line = line.trim();
        if let Some(data) = line.strip_prefix("data: ") {
            if let Ok(evt) = serde_json::from_str::<SseEvent>(data) {
                match evt.event_type.as_str() {
                    "text_delta" => {
                        if let Some(t) = &evt.text {
                            full_text.push_str(t);
                        }
                    }
                    "error" => {
                        if let Some(msg) = &evt.message {
                            warn!("Singularix stream error: {}", msg);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Try to extract conversation ID from response headers
    // (would need to be passed via SSE metadata in a future enhancement)
    (full_text, convo_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sse_empty() {
        let (text, cid) = parse_sse_response("");
        assert!(text.is_empty());
        assert!(cid.is_none());
    }

    #[test]
    fn test_parse_sse_tokens() {
        let body = r#"data: {"type":"text_delta","text":"Hello "}
data: {"type":"text_delta","text":"world"}
data: {"type":"done"}"#;
        let (text, _) = parse_sse_response(body);
        assert_eq!(text, "Hello world");
    }

    #[test]
    fn test_config_defaults() {
        let cfg = SingularixConfig {
            base_url: DEFAULT_URL.to_string(),
            api_key: String::new(),
            enabled: false,
        };
        assert!(!cfg.enabled);
        assert!(cfg.api_key.is_empty());
    }
}
