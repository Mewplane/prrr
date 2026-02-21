// FRD: specs/frds/FRD-P006.md

//! API error types and HTTP response mapping.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::registry::RegistryError;

/// API error response body (JSON).
#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
    code: u16,
}

/// API error enum with automatic HTTP status code mapping.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// 400 Bad Request — malformed input.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// 401 Unauthorized — missing or invalid credentials.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// 404 Not Found — resource does not exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// 409 Conflict — duplicate resource.
    #[error("conflict: {0}")]
    Conflict(String),

    /// 500 Internal Server Error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    /// Returns the HTTP status code for this error variant.
    fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = ErrorBody {
            error: self.to_string(),
            code: status.as_u16(),
        };
        (status, axum::Json(body)).into_response()
    }
}

impl From<RegistryError> for ApiError {
    fn from(err: RegistryError) -> Self {
        match err {
            RegistryError::DuplicateName(name) => Self::Conflict(format!("client name already exists: {name}")),
            RegistryError::DuplicatePublicKey => Self::Conflict("client with this public key already exists".into()),
            RegistryError::SubnetExhausted => Self::Internal("no free IP addresses available".into()),
            RegistryError::ClientNotFound(id) => Self::NotFound(format!("client not found: {id}")),
            RegistryError::InvalidSubnet(msg) => Self::Internal(format!("invalid subnet: {msg}")),
            RegistryError::Io { path, source } => Self::Internal(format!("I/O error at {}: {source}", path.display())),
            RegistryError::Serialization(msg) => Self::Internal(format!("serialization error: {msg}")),
            RegistryError::Database(msg) => Self::Internal(format!("database error: {msg}")),
        }
    }
}

#[cfg(test)]
mod tests {
    // FRD: specs/frds/FRD-P006.md
    use super::*;
    use axum::http::StatusCode;
    use uuid::Uuid;

    #[test]
    fn api_error_bad_request_maps_to_400() {
        let err = ApiError::BadRequest("invalid input".into());
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn api_error_unauthorized_maps_to_401() {
        let err = ApiError::Unauthorized("bad token".into());
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn api_error_not_found_maps_to_404() {
        let err = ApiError::NotFound("missing".into());
        assert_eq!(err.status_code(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn api_error_conflict_maps_to_409() {
        let err = ApiError::Conflict("duplicate".into());
        assert_eq!(err.status_code(), StatusCode::CONFLICT);
    }

    #[test]
    fn api_error_internal_maps_to_500() {
        let err = ApiError::Internal("crash".into());
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn registry_duplicate_name_maps_to_conflict() {
        let err: ApiError = RegistryError::DuplicateName("alice".into()).into();
        assert_eq!(err.status_code(), StatusCode::CONFLICT);
        assert!(err.to_string().contains("alice"));
    }

    #[test]
    fn registry_duplicate_key_maps_to_conflict() {
        let err: ApiError = RegistryError::DuplicatePublicKey.into();
        assert_eq!(err.status_code(), StatusCode::CONFLICT);
    }

    #[test]
    fn registry_subnet_exhausted_maps_to_internal() {
        let err: ApiError = RegistryError::SubnetExhausted.into();
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn registry_client_not_found_maps_to_not_found() {
        let id = Uuid::new_v4();
        let err: ApiError = RegistryError::ClientNotFound(id).into();
        assert_eq!(err.status_code(), StatusCode::NOT_FOUND);
        assert!(err.to_string().contains(&id.to_string()));
    }

    #[test]
    fn registry_invalid_subnet_maps_to_internal() {
        let err: ApiError = RegistryError::InvalidSubnet("bad cidr".into()).into();
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn registry_io_error_maps_to_internal() {
        let err: ApiError = RegistryError::Io {
            path: std::path::PathBuf::from("/tmp/test"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "file gone"),
        }
        .into();
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(err.to_string().contains("/tmp/test"));
    }

    #[test]
    fn registry_serialization_error_maps_to_internal() {
        let err: ApiError = RegistryError::Serialization("bad json".into()).into();
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn registry_database_error_maps_to_internal() {
        let err: ApiError = RegistryError::Database("connection failed".into()).into();
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(err.to_string().contains("database error"));
    }
}
