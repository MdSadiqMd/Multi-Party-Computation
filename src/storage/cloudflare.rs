use crate::error::{MpcError, Result};
use worker::*;

pub async fn store(env: &Env, region: &str, data: &str) -> Result<String> {
    console_log!("Storing data in region: {}", region);

    let bucket = env
        .bucket("SHARES_BUCKET")
        .map_err(|e| MpcError::ConfigError(format!("Failed to get R2 bucket: {}", e)))?;

    let object_key = format!("shares/{}.json", uuid::Uuid::new_v4());

    let data_bytes = data.as_bytes().to_vec();
    let _put_result = bucket
        .put(&object_key, data_bytes)
        .execute()
        .await
        .map_err(|e| MpcError::StorageError(format!("Failed to store in R2: {}", e)))?;

    Ok(object_key)
}
