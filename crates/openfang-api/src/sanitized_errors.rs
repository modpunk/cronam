#![deny(unsafe_code)]
//! Sanitized error responses (Ralph Layer 30).
//!
//! Returns generic, non-leaking error messages to API consumers while logging
//! full internal details to the audit trail. Prevents architecture disclosure
//! through error messages.

use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use tracing::error;
use uuid::Uuid;

/// An error that has been sanitized for user-facing output.
///
/// The internal details are logged with a correlation ID so operators can
/// find the full error in the audit trail.
pub struct SanitizedError {
    /// HTTP status code.
    pub status: StatusCode,
    /// Generic user-facing message (no internal details).
    pub user_message: &'static str,
    /// Correlation ID for the audit trail.
    pub correlation_id: String,
}

impl SanitizedError {
    /// Create a sanitized error, logging the internal details.
    ///
    /// The `internal_detail` is written to the tracing log with the correlation
    /// ID but is NEVER included in the API response.
    pub fn new(
        status: StatusCode,
        user_message: &'static str,
        internal_detail: &str,
    ) -> Self {
        let correlation_id = Uuid::new_v4().to_string();
        error!(
            correlation_id = %correlation_id,
            internal_detail = %internal_detail,
            status = %status.as_u16(),
            "Sanitized error — user sees generic message"
        );
        Self {
            status,
            user_message,
            correlation_id,
        }
    }

    /// Convert to an Axum JSON response tuple.
    pub fn into_response(self) -> (StatusCode, Json<Value>) {
        (
            self.status,
            Json(json!({
                "error": self.user_message,
                "correlation_id": self.correlation_id,
            })),
        )
    }
}

// ---------------------------------------------------------------------------
// Convenience constructors for common error categories
// ---------------------------------------------------------------------------

/// Agent operation failed (spawn, message, kill).
pub fn agent_error(internal: &str) -> (StatusCode, Json<Value>) {
    SanitizedError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Agent operation failed. Check the correlation_id in server logs for details.",
        internal,
    )
    .into_response()
}

/// Resource not found.
pub fn not_found(resource: &'static str) -> (StatusCode, Json<Value>) {
    SanitizedError::new(
        StatusCode::NOT_FOUND,
        resource,
        resource,
    )
    .into_response()
}

/// Validation error (safe to return — user-provided data is not internal state).
pub fn validation_error(message: &'static str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": message })),
    )
}

/// Secret/config write failed.
pub fn config_error(internal: &str) -> (StatusCode, Json<Value>) {
    SanitizedError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Configuration operation failed. Check server logs for details.",
        internal,
    )
    .into_response()
}

/// Message delivery failed.
pub fn delivery_error(internal: &str) -> (StatusCode, Json<Value>) {
    SanitizedError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Message delivery failed. Check server logs for details.",
        internal,
    )
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitized_error_does_not_leak_internals() {
        let err = SanitizedError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Operation failed.",
            "wasmtime::Engine panicked at fuel_limit overflow in sandbox.rs:178",
        );
        let (status, Json(body)) = err.into_response();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        // User-facing message must NOT contain internal details
        let body_str = body.to_string();
        assert!(!body_str.contains("wasmtime"));
        assert!(!body_str.contains("sandbox.rs"));
        assert!(!body_str.contains("fuel_limit"));
        assert!(body_str.contains("Operation failed."));
        assert!(body_str.contains("correlation_id"));
    }

    #[test]
    fn validation_errors_are_safe_to_return() {
        let (status, Json(body)) = validation_error("Invalid agent ID");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "Invalid agent ID");
    }
}
