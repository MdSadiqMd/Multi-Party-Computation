use crate::error::{MpcError, Result};
use aws_sdk_s3::Client;

pub async fn retrieve(pubkey: &str) -> Result<Vec<String>> {
    let config = aws_config::load_from_env().await;
    let client = Client::new(&config);
    let bucket_name = std::env::var("AWS_BUCKET")
        .map_err(|_| MpcError::ConfigError("AWS_BUCKET not set".into()))?;

    let prefix = format!("shares/{}/", pubkey);
    let mut shares = Vec::new();

    let list = client
        .list_objects_v2()
        .bucket(&bucket_name)
        .prefix(&prefix)
        .send()
        .await?;
    for object in list.contents().unwrap_or_default() {
        let key = object.key().unwrap();
        let data = client
            .get_object()
            .bucket(&bucket_name)
            .key(key)
            .send()
            .await?
            .body
            .collect()
            .await
            .map_err(|e| MpcError::StorageError(format!("Failed to collect object data: {}", e)))?;

        let share = String::from_utf8(data.to_vec())?;
        shares.push(share);
    }

    Ok(shares)
}
