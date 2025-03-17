use crate::error::{MpcError, Result};
use worker::*;

pub async fn retrieve(env: &Env, pubkey: &str) -> Result<Vec<String>> {
    let bucket = env
        .bucket("SHARES_BUCKET")
        .map_err(|e| MpcError::ConfigError(format!("Failed to get R2 bucket: {}", e)))?;

    let prefix = format!("shares/{}/", pubkey);
    let mut shares = Vec::new();

    let list = bucket
        .list()
        .prefix(&prefix)
        .execute()
        .await
        .map_err(|e| MpcError::StorageError(format!("Failed to list objects: {}", e)))?;

    for object in list.objects() {
        let key = object.key();
        let data = bucket
            .get(&key)
            .execute()
            .await
            .map_err(|e| MpcError::StorageError(format!("Failed to get object: {}", e)))?;

        let data =
            data.ok_or_else(|| MpcError::StorageError("Failed to get object data".into()))?;
        let bytes = data
            .body()
            .ok_or_else(|| MpcError::StorageError("Failed to get object body".into()))?
            .bytes()
            .await
            .map_err(|e| MpcError::StorageError(format!("Failed to read object body: {}", e)))?;

        let share = String::from_utf8(bytes).map_err(|e| {
            MpcError::StorageError(format!("Failed to convert bytes to string: {}", e))
        })?;
        shares.push(share);
    }

    Ok(shares)
}
