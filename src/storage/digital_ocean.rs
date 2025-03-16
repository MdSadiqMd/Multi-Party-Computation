use crate::error::{MpcError, Result};
use digitalocean::prelude::*;

pub async fn store(region: &str, data: &str) -> Result<String> {
    let token =
        std::env::var("DO_TOKEN").map_err(|_| MpcError::ConfigError("DO_TOKEN not set".into()))?;

    let spaces = SpacesApi::new(token);
    let space_name =
        std::env::var("DO_SPACE").map_err(|_| MpcError::ConfigError("DO_SPACE not set".into()))?;

    let object_key = format!("shares/{}.json", uuid::Uuid::new_v4());

    spaces
        .upload(&space_name, &object_key, data.as_bytes())
        .region(region)
        .send()
        .await
        .map_err(|e| MpcError::StorageError(e.to_string()))?;

    Ok(object_key)
}
