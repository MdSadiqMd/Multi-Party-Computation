use crate::error::{MpcError, Result};
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_s3::{primitives::ByteStream, Client};
use std::sync::Arc;

/// AWS S3 storage provider with KMS encryption
pub struct AwsStorage {
    s3_client: Arc<Client>,
    kms_client: Arc<KmsClient>,
    bucket_name: String,
    kms_key_id: Option<String>,
}

impl AwsStorage {
    pub async fn new() -> Result<Self> {
        let config = aws_config::load_from_env().await;
        let s3_client = Client::new(&config);
        let kms_client = KmsClient::new(&config);

        let bucket_name =
            std::env::var("AWS_S3_BUCKET").unwrap_or_else(|_| "mpc-shares-bucket".to_string());

        let kms_key_id = std::env::var("AWS_KMS_KEY_ID").ok();

        Ok(AwsStorage {
            s3_client: Arc::new(s3_client),
            kms_client: Arc::new(kms_client),
            bucket_name,
            kms_key_id,
        })
    }
}

/// Store data in S3 with server-side encryption
pub async fn store(key: &str, data: &[u8], region: &str) -> Result<String> {
    let storage = AwsStorage::new().await?;

    let mut put_request = storage
        .s3_client
        .put_object()
        .bucket(&storage.bucket_name)
        .key(format!("{}/{}", region, key))
        .body(ByteStream::from(data.to_vec()));

    // Add KMS encryption if configured
    if let Some(kms_key) = &storage.kms_key_id {
        put_request = put_request
            .server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::AwsKms)
            .ssekms_key_id(kms_key);
    } else {
        // Use AES256 encryption by default
        put_request =
            put_request.server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::Aes256);
    }

    put_request
        .send()
        .await
        .map_err(|e| MpcError::AwsS3Error(format!("Failed to store object: {}", e)))?;

    Ok(format!("{}/{}", region, key))
}

/// Retrieve data from S3
pub async fn retrieve(key: &str) -> Result<Vec<String>> {
    let storage = AwsStorage::new().await?;

    let response = storage
        .s3_client
        .get_object()
        .bucket(&storage.bucket_name)
        .key(key)
        .send()
        .await
        .map_err(|e| MpcError::AwsS3Error(format!("Failed to get object: {}", e)))?;

    let data = response
        .body
        .collect()
        .await
        .map_err(|e| MpcError::StorageError(format!("Failed to collect data: {}", e)))?;

    let content = String::from_utf8(data.to_vec())?;
    Ok(vec![content])
}

/// List keys with prefix
pub async fn list_keys(prefix: &str) -> Result<Vec<String>> {
    let storage = AwsStorage::new().await?;

    let mut keys = Vec::new();
    let mut continuation_token = None;

    loop {
        let mut request = storage
            .s3_client
            .list_objects_v2()
            .bucket(&storage.bucket_name)
            .prefix(prefix);

        if let Some(token) = continuation_token {
            request = request.continuation_token(token);
        }

        let response = request.send().await?;

        for object in response.contents().unwrap_or_default() {
            if let Some(key) = object.key() {
                keys.push(key.to_string());
            }
        }

        if response.is_truncated() {
            continuation_token = response.next_continuation_token().map(|s| s.to_string());
        } else {
            break;
        }
    }

    Ok(keys)
}

/// Delete an object from S3
pub async fn delete(key: &str) -> Result<()> {
    let storage = AwsStorage::new().await?;

    storage
        .s3_client
        .delete_object()
        .bucket(&storage.bucket_name)
        .key(key)
        .send()
        .await
        .map_err(|e| MpcError::AwsS3Error(format!("Failed to delete object: {}", e)))?;

    Ok(())
}

/// Create bucket if it doesn't exist
pub async fn ensure_bucket_exists() -> Result<()> {
    let storage = AwsStorage::new().await?;

    // Check if bucket exists
    match storage
        .s3_client
        .head_bucket()
        .bucket(&storage.bucket_name)
        .send()
        .await
    {
        Ok(_) => Ok(()),
        Err(_) => {
            // Create bucket
            storage
                .s3_client
                .create_bucket()
                .bucket(&storage.bucket_name)
                .send()
                .await
                .map_err(|e| MpcError::AwsS3Error(format!("Failed to create bucket: {}", e)))?;

            // Enable versioning
            storage
                .s3_client
                .put_bucket_versioning()
                .bucket(&storage.bucket_name)
                .versioning_configuration(
                    aws_sdk_s3::types::VersioningConfiguration::builder()
                        .status(aws_sdk_s3::types::BucketVersioningStatus::Enabled)
                        .build(),
                )
                .send()
                .await
                .map_err(|e| MpcError::AwsS3Error(format!("Failed to enable versioning: {}", e)))?;

            Ok(())
        }
    }
}
