use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::operation::{get_object::GetObjectError, list_objects_v2::ListObjectsV2Error};
use axum::http;
use axum::{
    response::{IntoResponse, Response},
    Json,
};
use http::StatusCode;
use serde_json::json;
use std::string::FromUtf8Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MpcError {
    #[error("Invalid metadata configuration")]
    InvalidMetadata,

    #[error("Invalid secret")]
    InvalidSecret,

    #[error("Invalid share")]
    InvalidShare,

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("AWS S3 error: {0}")]
    AwsS3Error(String),

    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] FromUtf8Error),

    #[error("Cryptography error: {0}")]
    CryptoError(String),

    #[error("Queue processing error: {0}")]
    QueueError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, MpcError>;

impl From<SdkError<ListObjectsV2Error>> for MpcError {
    fn from(err: SdkError<ListObjectsV2Error>) -> Self {
        MpcError::AwsS3Error(format!("ListObjectsV2Error: {}", err))
    }
}

impl From<SdkError<GetObjectError>> for MpcError {
    fn from(err: SdkError<GetObjectError>) -> Self {
        MpcError::AwsS3Error(format!("GetObjectError: {}", err))
    }
}

impl IntoResponse for MpcError {
    fn into_response(self) -> Response {
        let status = match self {
            MpcError::InvalidMetadata => StatusCode::BAD_REQUEST,
            MpcError::InvalidSecret => StatusCode::BAD_REQUEST,
            MpcError::InvalidShare => StatusCode::BAD_REQUEST,
            MpcError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            MpcError::AwsS3Error(_) => StatusCode::INTERNAL_SERVER_ERROR,
            MpcError::Utf8Error(_) => StatusCode::INTERNAL_SERVER_ERROR,
            MpcError::CryptoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            MpcError::QueueError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            MpcError::ConfigError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = Json(json!({
            "error": self.to_string(),
        }));

        (status, body).into_response()
    }
}
