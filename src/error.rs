use std::path::PathBuf;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("CONFIGDECK_ENV is required")]
    MissingEnvironment,
    #[error("CONFIGDECK_ENV must be development, test, or production")]
    InvalidEnvironment,
    #[error("invalid bind address")]
    InvalidBindAddress,
    #[error("database pool size must be between 1 and 16")]
    InvalidDatabasePoolSize,
    #[error("master key file is missing: {0}")]
    MissingMasterKey(PathBuf),
    #[error("unable to read master key file {path}")]
    ReadMasterKey {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("master key must use standard base64 encoding")]
    InvalidMasterKeyEncoding,
    #[error("master key must decode to exactly 32 bytes")]
    InvalidMasterKeyLength,
    #[error("bootstrap admin email and password must be provided together")]
    IncompleteBootstrapCredentials,
    #[error("invalid trusted proxy network")]
    InvalidTrustedProxy,
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("database migration failed")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("authentication failed")]
    Authentication,
    #[error("authentication is required")]
    Unauthorized,
    #[error("organization setup is required")]
    OrganizationSetupRequired,
    #[error("initial password change is required")]
    PasswordChangeRequired,
    #[error("operation is not permitted")]
    Forbidden,
    #[error("request rate limit exceeded")]
    RateLimited,
    #[error("invalid request")]
    InvalidRequest,
    #[error("resource was not found")]
    NotFound,
    #[error("resource conflicts with existing state")]
    Conflict,
    #[error("template rendering failed")]
    Template(#[from] askama::Error),
    #[error("internal operation failed")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if matches!(self, Self::OrganizationSetupRequired) {
            return Redirect::to("/setup/organization").into_response();
        }
        if matches!(self, Self::PasswordChangeRequired) {
            return Redirect::to("/account/password").into_response();
        }
        let (status, message) = match self {
            Self::Authentication | Self::InvalidRequest => {
                (StatusCode::BAD_REQUEST, "Unable to process request.")
            }
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "Authentication required."),
            Self::Forbidden => (StatusCode::FORBIDDEN, "Operation not permitted."),
            Self::NotFound => (StatusCode::NOT_FOUND, "Resource not found."),
            Self::Conflict => (
                StatusCode::CONFLICT,
                "Unable to save because the resource already exists or changed.",
            ),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "Please try again later."),
            Self::Database(_)
            | Self::Migration(_)
            | Self::Crypto
            | Self::Template(_)
            | Self::Internal(_) => {
                tracing::error!(error = %self, "request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Unable to complete request.",
                )
            }
            Self::OrganizationSetupRequired | Self::PasswordChangeRequired => unreachable!(),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
