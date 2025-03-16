use crate::error::{MpcError, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct MemoryStorage {
    storage: Arc<Mutex<HashMap<String, String>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            storage: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn store(&self, _region: &str, data: &str) -> Result<String> {
        let key = uuid::Uuid::new_v4().to_string();
        let mut storage = self
            .storage
            .lock()
            .map_err(|e| MpcError::StorageError(format!("Failed to acquire lock: {}", e)))?;
        storage.insert(key.clone(), data.to_string());
        Ok(key)
    }

    pub async fn retrieve(&self, key: &str) -> Result<String> {
        let storage = self
            .storage
            .lock()
            .map_err(|e| MpcError::StorageError(format!("Failed to acquire lock: {}", e)))?;
        storage
            .get(key)
            .cloned()
            .ok_or_else(|| MpcError::StorageError("Key not found".into()))
    }
}
