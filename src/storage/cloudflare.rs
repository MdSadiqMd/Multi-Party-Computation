use crate::error::{MpcError, Result};
use serde_json;
use worker::*;

/// Cloudflare R2 storage implementation
pub struct CloudflareStorage<'a> {
    bucket: Bucket,
    kv: Option<kv::KvStore>,
    env: &'a Env,
}

impl<'a> CloudflareStorage<'a> {
    pub fn new(env: &'a Env) -> Result<Self> {
        let bucket = env
            .bucket("SHARES_BUCKET")
            .map_err(|e| MpcError::ConfigError(format!("Failed to get R2 bucket: {}", e)))?;

        let kv = env.kv("SHARES_METADATA").ok();

        Ok(CloudflareStorage { bucket, kv, env })
    }
}

/// Store data in Cloudflare R2
pub async fn store(env: &Env, key: &str, data: &[u8]) -> Result<String> {
    let storage = CloudflareStorage::new(env)?;

    // Store in R2
    storage
        .bucket
        .put(key, data.to_vec())
        .execute()
        .await
        .map_err(|e| MpcError::StorageError(format!("Failed to store in R2: {}", e)))?;

    // Store metadata in KV if available
    if let Some(kv) = &storage.kv {
        let metadata = serde_json::json!({
            "size": data.len(),
            "created_at": chrono::Utc::now().to_rfc3339(),
            "content_type": "application/octet-stream",
        });

        kv.put(key, metadata.to_string())
            .map_err(|e| MpcError::StorageError(format!("Failed to store metadata: {}", e)))?
            .expiration_ttl(86400 * 30) // 30 days
            .execute()
            .await
            .map_err(|e| MpcError::StorageError(format!("Failed to execute KV put: {}", e)))?;
    }

    Ok(key.to_string())
}

/// Retrieve data from Cloudflare R2
pub async fn retrieve(env: &Env, key: &str) -> Result<Vec<String>> {
    let storage = CloudflareStorage::new(env)?;

    let object = storage
        .bucket
        .get(key)
        .execute()
        .await
        .map_err(|e| MpcError::StorageError(format!("Failed to get object: {}", e)))?;

    let object =
        object.ok_or_else(|| MpcError::StorageError(format!("Object not found: {}", key)))?;

    let body = object
        .body()
        .ok_or_else(|| MpcError::StorageError("Object has no body".into()))?;

    let bytes = body
        .bytes()
        .await
        .map_err(|e| MpcError::StorageError(format!("Failed to read body: {}", e)))?;

    let content = String::from_utf8(bytes)
        .map_err(|e| MpcError::StorageError(format!("Invalid UTF-8: {}", e)))?;

    Ok(vec![content])
}

/// List keys with prefix
pub async fn list_keys(env: &Env, prefix: &str) -> Result<Vec<String>> {
    let storage = CloudflareStorage::new(env)?;

    let mut keys = Vec::new();
    let mut cursor = None;

    loop {
        let mut list_request = storage.bucket.list();
        list_request = list_request.prefix(prefix);

        if let Some(c) = cursor {
            list_request = list_request.cursor(c);
        }

        let response = list_request
            .execute()
            .await
            .map_err(|e| MpcError::StorageError(format!("Failed to list objects: {}", e)))?;

        for object in response.objects() {
            keys.push(object.key().to_string());
        }

        if response.truncated() {
            cursor = response.cursor().map(|s| s.to_string());
        } else {
            break;
        }
    }

    Ok(keys)
}

/// Delete object from R2
pub async fn delete(env: &Env, key: &str) -> Result<()> {
    let storage = CloudflareStorage::new(env)?;

    storage
        .bucket
        .delete(key)
        .await
        .map_err(|e| MpcError::StorageError(format!("Failed to delete object: {}", e)))?;

    // Delete metadata if KV is available
    if let Some(kv) = &storage.kv {
        kv.delete(key)
            .await
            .map_err(|e| MpcError::StorageError(format!("Failed to delete metadata: {}", e)))?;
    }

    Ok(())
}

/// Get object metadata from KV
pub async fn get_metadata(env: &Env, key: &str) -> Result<Option<String>> {
    let storage = CloudflareStorage::new(env)?;

    if let Some(kv) = &storage.kv {
        let value = kv
            .get(key)
            .text()
            .await
            .map_err(|e| MpcError::StorageError(format!("Failed to get metadata: {}", e)))?;
        Ok(value)
    } else {
        Ok(None)
    }
}
