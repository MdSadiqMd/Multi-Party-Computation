use crate::error::{MpcError, Result};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredValue {
    data: Vec<u8>,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    metadata: Option<String>,
}

/// In-memory storage with TTL support
#[derive(Clone)]
pub struct MemoryStorage {
    storage: Arc<DashMap<String, StoredValue>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        let storage = Arc::new(DashMap::new());

        // Start background cleanup task
        let storage_clone = storage.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                Self::cleanup_expired(&storage_clone);
            }
        });

        Self { storage }
    }

    /// Store data with optional TTL
    pub async fn store(&self, key: &str, data: &[u8]) -> Result<String> {
        let value = StoredValue {
            data: data.to_vec(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::days(30)),
            metadata: None,
        };

        self.storage.insert(key.to_string(), value);
        Ok(key.to_string())
    }

    /// Store with metadata
    pub async fn store_with_metadata(
        &self,
        key: &str,
        data: &[u8],
        metadata: &str,
        ttl_seconds: Option<i64>,
    ) -> Result<String> {
        let expires_at = ttl_seconds.map(|ttl| Utc::now() + Duration::seconds(ttl));

        let value = StoredValue {
            data: data.to_vec(),
            created_at: Utc::now(),
            expires_at,
            metadata: Some(metadata.to_string()),
        };

        self.storage.insert(key.to_string(), value);
        Ok(key.to_string())
    }

    /// Retrieve data
    pub async fn retrieve(&self, key: &str) -> Result<Vec<String>> {
        if let Some(entry) = self.storage.get(key) {
            // Check expiration
            if let Some(expires_at) = entry.expires_at {
                if Utc::now() > expires_at {
                    drop(entry);
                    self.storage.remove(key);
                    return Err(MpcError::StorageError("Key expired".into()));
                }
            }

            let content = String::from_utf8(entry.data.clone())
                .map_err(|e| MpcError::StorageError(format!("Invalid UTF-8: {}", e)))?;
            Ok(vec![content])
        } else {
            Err(MpcError::StorageError(format!("Key not found: {}", key)))
        }
    }

    /// List keys with prefix
    pub async fn list_keys(&self, prefix: &str) -> Result<Vec<String>> {
        let now = Utc::now();
        let keys: Vec<String> = self
            .storage
            .iter()
            .filter_map(|entry| {
                let key = entry.key();
                let value = entry.value();

                // Check prefix and expiration
                if key.starts_with(prefix) {
                    if let Some(expires_at) = value.expires_at {
                        if now <= expires_at {
                            Some(key.clone())
                        } else {
                            None
                        }
                    } else {
                        Some(key.clone())
                    }
                } else {
                    None
                }
            })
            .collect();

        Ok(keys)
    }

    /// Delete a key
    pub async fn delete(&self, key: &str) -> Result<()> {
        self.storage.remove(key);
        Ok(())
    }

    /// Get storage statistics
    pub fn stats(&self) -> StorageStats {
        let total_keys = self.storage.len();
        let mut total_size = 0;
        let mut expired_count = 0;
        let now = Utc::now();

        for entry in self.storage.iter() {
            total_size += entry.value().data.len();
            if let Some(expires_at) = entry.value().expires_at {
                if now > expires_at {
                    expired_count += 1;
                }
            }
        }

        StorageStats {
            total_keys,
            total_size,
            expired_count,
        }
    }

    /// Clean up expired entries
    fn cleanup_expired(storage: &DashMap<String, StoredValue>) {
        let now = Utc::now();
        let expired_keys: Vec<String> = storage
            .iter()
            .filter_map(|entry| {
                if let Some(expires_at) = entry.value().expires_at {
                    if now > expires_at {
                        Some(entry.key().clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        for key in expired_keys {
            storage.remove(&key);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub total_keys: usize,
    pub total_size: usize,
    pub expired_count: usize,
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let storage = MemoryStorage::new();
        let key = "test_key";
        let data = b"test data";

        // Store
        let stored_key = storage.store(key, data).await.unwrap();
        assert_eq!(stored_key, key);

        // Retrieve
        let retrieved = storage.retrieve(key).await.unwrap();
        assert_eq!(retrieved[0].as_bytes(), data);
    }

    #[tokio::test]
    async fn test_list_keys() {
        let storage = MemoryStorage::new();

        // Store multiple keys
        storage.store("prefix/key1", b"data1").await.unwrap();
        storage.store("prefix/key2", b"data2").await.unwrap();
        storage.store("other/key3", b"data3").await.unwrap();

        // List with prefix
        let keys = storage.list_keys("prefix/").await.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"prefix/key1".to_string()));
        assert!(keys.contains(&"prefix/key2".to_string()));
    }
}
