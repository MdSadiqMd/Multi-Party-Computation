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

    pub async fn retrieve(&self, key: &str) -> Result<Vec<String>> {
        let storage = self
            .storage
            .lock()
            .map_err(|e| MpcError::StorageError(format!("Failed to acquire lock: {}", e)))?;

        let shares = storage
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("shares/{}/", key)))
            .map(|(_, v)| v.clone())
            .collect();

        Ok(shares)
    }
}
