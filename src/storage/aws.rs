use crate::error::{MpcError, Result};
use aws_sdk_s3::Client;

pub async fn store(region: &str, data: &str) -> Result<String> {
    let config = aws_config::from_env().region(region).load().await;

    let client = Client::new(&config);
    let bucket_name = std::env::var("AWS_BUCKET")
        .map_err(|_| MpcError::ConfigError("AWS_BUCKET not set".into()))?;

    let object_key = format!("shares/{}.json", uuid::Uuid::new_v4());

    client
        .put_object()
        .bucket(bucket_name)
        .key(&object_key)
        .body(data.as_bytes().to_owned().into())
        .send()
        .await
        .map_err(|e| MpcError::StorageError(e.to_string()))?;

    Ok(object_key)
}
