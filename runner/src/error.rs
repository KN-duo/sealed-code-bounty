//! HTTP error type with explicit status mapping.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    /// Intent signature failed — 403, never retried by sane relayers.
    IntentForbidden(String),
    NotFound(String),
    Conflict(String),
    PayloadTooLarge(String),
    RateLimited(u64),
    StorageFull,
    NotImplemented(String),
    Internal(String),
}

impl ApiError {
    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::IntentForbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ApiError::RateLimited(retry_after) => {
                let _ = retry_after;
                StatusCode::TOO_MANY_REQUESTS
            }
            ApiError::StorageFull => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "bad_request",
            ApiError::IntentForbidden(_) => "intent_signature_invalid",
            ApiError::NotFound(_) => "not_found",
            ApiError::Conflict(_) => "chain_view_divergence",
            ApiError::PayloadTooLarge(_) => "payload_too_large",
            ApiError::RateLimited(_) => "rate_limited",
            ApiError::StorageFull => "storage_full",
            ApiError::NotImplemented(_) => "not_implemented",
            ApiError::Internal(_) => "internal",
        }
    }

    fn message(&self) -> String {
        match self {
            ApiError::BadRequest(m)
            | ApiError::IntentForbidden(m)
            | ApiError::NotFound(m)
            | ApiError::Conflict(m)
            | ApiError::PayloadTooLarge(m)
            | ApiError::NotImplemented(m)
            | ApiError::Internal(m) => m.clone(),
            ApiError::RateLimited(retry) => {
                format!("rate limited; retry after {retry}s")
            }
            ApiError::StorageFull => {
                "global storage cap reached; try again later".to_string()
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut resp = (self.status(), Json(json!({ "error": self.code(), "message": self.message() }))).into_response();
        if let ApiError::RateLimited(retry) = &self {
            if let Ok(v) = retry.to_string().parse() {
                resp.headers_mut().insert("retry-after", v);
            }
        }
        resp
    }
}

impl From<crate::unpack::UnpackError> for ApiError {
    fn from(e: crate::unpack::UnpackError) -> Self {
        match e {
            crate::unpack::UnpackError::TotalSizeExceeded { .. } => {
                ApiError::BadRequest(format!("environment rejected: {e}"))
            }
            other => ApiError::BadRequest(format!("environment unpack failed: {other}")),
        }
    }
}
