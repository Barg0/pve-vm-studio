use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Every API error becomes {"error": "..."} with a fitting status.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }

    pub fn not_found(what: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, what)
    }

    pub fn bad_request(what: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, what)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            tracing::error!("{}", self.message);
        }
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

/// Anything else that fails (PVE unreachable, database...) is a 502/500 with the reason.
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, format!("{e:#}"))
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, format!("database: {e}"))
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
