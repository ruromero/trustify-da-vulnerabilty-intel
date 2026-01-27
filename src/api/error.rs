//! Unified API error handling
//!
//! This module provides a consistent error response format across all API endpoints.

use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::Serialize;
use uuid::Uuid;

/// Standard error response format
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Error type/code
    pub error: String,
    /// Human-readable error message
    pub message: String,
    /// Unique request ID for tracing
    pub request_id: String,
}

/// Unified API error type
///
/// All API endpoints should return `Result<T, ApiError>` for consistent error handling.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApiError {
    /// Resource not found (404)
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Vulnerability not found (404)
    #[error("Vulnerability not found: {0}")]
    VulnerabilityNotFound(String),

    /// Document not found (404)
    #[error("Document not found: {0}")]
    DocumentNotFound(String),

    /// Bad request / validation error (400)
    #[error("Invalid request: {0}")]
    #[allow(dead_code)] // Reserved for future request validation
    BadRequest(String),

    /// Internal server error (500)
    #[error("Internal server error: {0}")]
    Internal(String),

    /// Database error (500)
    #[error("Database error: {0}")]
    Database(String),

    /// External service error (502)
    #[error("External service error: {0}")]
    ExternalService(String),
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            ApiError::NotFound(_)
            | ApiError::VulnerabilityNotFound(_)
            | ApiError::DocumentNotFound(_) => StatusCode::NOT_FOUND,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::ExternalService(_) => StatusCode::BAD_GATEWAY,
            ApiError::Internal(_) | ApiError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        let error_type = match self {
            ApiError::NotFound(_) => "not_found",
            ApiError::VulnerabilityNotFound(_) => "vulnerability_not_found",
            ApiError::DocumentNotFound(_) => "document_not_found",
            ApiError::BadRequest(_) => "bad_request",
            ApiError::Internal(_) => "internal_error",
            ApiError::Database(_) => "database_error",
            ApiError::ExternalService(_) => "external_service_error",
        };

        tracing::error!(
            error_type = error_type,
            status = status.as_u16(),
            message = %self,
            "API error"
        );

        HttpResponse::build(status).json(ErrorResponse {
            error: error_type.to_string(),
            message: self.to_string(),
            request_id: Uuid::new_v4().to_string(),
        })
    }
}

// ============================================================================
// From conversions for service errors
// ============================================================================

impl From<crate::service::vulnerability::VulnerabilityServiceError> for ApiError {
    fn from(err: crate::service::vulnerability::VulnerabilityServiceError) -> Self {
        match err {
            crate::service::vulnerability::VulnerabilityServiceError::NotFound(id) => {
                ApiError::VulnerabilityNotFound(id)
            }
            crate::service::vulnerability::VulnerabilityServiceError::Internal(msg) => {
                ApiError::Internal(msg)
            }
        }
    }
}

impl From<crate::service::document::DocumentServiceError> for ApiError {
    fn from(err: crate::service::document::DocumentServiceError) -> Self {
        match err {
            crate::service::document::DocumentServiceError::DbError(
                crate::db::DbError::NotFound(id),
            ) => ApiError::DocumentNotFound(id),
            crate::service::document::DocumentServiceError::DbError(e) => {
                ApiError::Database(e.to_string())
            }
            crate::service::document::DocumentServiceError::RetrieverError(e) => {
                ApiError::ExternalService(e.to_string())
            }
        }
    }
}

impl From<crate::service::remediation::RemediationError> for ApiError {
    fn from(err: crate::service::remediation::RemediationError) -> Self {
        match err {
            crate::service::remediation::RemediationError::AssessmentFailed(msg) => {
                ApiError::Internal(format!("Assessment failed: {}", msg))
            }
            crate::service::remediation::RemediationError::ActionGenerationFailed(msg) => {
                ApiError::Internal(format!("Action generation failed: {}", msg))
            }
        }
    }
}

impl From<crate::db::DbError> for ApiError {
    fn from(err: crate::db::DbError) -> Self {
        match err {
            crate::db::DbError::NotFound(id) => ApiError::NotFound(id),
            _ => ApiError::Database(err.to_string()),
        }
    }
}
