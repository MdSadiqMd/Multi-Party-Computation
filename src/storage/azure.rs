use crate::error::{MpcError, Result};
use azure_sdk_storage_blob::prelude::*;

pub async fn store(region: &str, data: &str) -> Result<String> {
    let account = std::env::var("AZURE_ACCOUNT")
        .map_err(|_| MpcError::ConfigError("AZURE_ACCOUNT not set".into()))?;

    let key = std::env::var("AZURE_KEY")
        .map_err(|_| MpcError::ConfigError("AZURE_KEY not set".into()))?;

    let container_name = std::env::var("AZURE_CONTAINER")
        .map_err(|_| MpcError::ConfigError("AZURE_CONTAINER not set".into()))?;

    let client = ClientBuilder::new(account, key).with_region(region).build();

    let blob_name = format!("shares/{}.json", uuid::Uuid::new_v4());

    client
        .put_block_blob()
        .with_container_name(&container_name)
        .with_blob_name(&blob_name)
        .with_content_type("application/json")
        .with_body(data.as_bytes())
        .execute()
        .await
        .map_err(|e| MpcError::StorageError(e.to_string()))?;

    Ok(blob_name)
}
