pub mod aws;
pub mod cloudflare;
pub mod memory;

use crate::{
    error::Result,
    meta::{metadata::CloudProvider, metadata::SecretMetadata, StorageLocation},
};
use aes_gcm::NewAead; // For version 0.9
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Nonce};
use rand_core::{OsRng, RngCore}; // Use rand_core directly
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::Env;

/// Encrypted share with metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedShare {
    pub share_id: String,
    pub participant_id: u32,
    pub encrypted_data: Vec<u8>,
    pub nonce: Vec<u8>,
    pub metadata: ShareMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShareMetadata {
    pub key_id: String,
    pub threshold: usize,
    pub total_shares: usize,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Storage trait for different providers
#[async_trait::async_trait]
pub trait StorageProvider: Send + Sync {
    async fn store(&self, key: &str, data: &[u8]) -> Result<String>;
    async fn retrieve(&self, key: &str) -> Result<Vec<u8>>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>>;
}

pub async fn distribute_shares(
    env: &Env,
    shares: Vec<Vec<u8>>,
    metadata: &SecretMetadata,
) -> Result<Vec<StorageLocation>> {
    let mut locations = Vec::new();
    let providers = select_providers(metadata);
    let key_id = Uuid::new_v4().to_string();

    // Generate encryption key (in production, use KMS)
    let mut key = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut key);
    let cipher = ChaCha20Poly1305::new((&key).into());

    for (index, share) in shares.into_iter().enumerate() {
        let participant_id = (index + 1) as u32;
        let provider = providers[index % providers.len()];
        let region = select_region(provider, metadata)?;

        // Encrypt share
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher.encrypt(nonce, share.as_ref()).map_err(|e| {
            crate::error::MpcError::CryptoError(format!("Encryption failed: {}", e))
        })?;

        let encrypted_share = EncryptedShare {
            share_id: format!("{}-{}", key_id, participant_id),
            participant_id,
            encrypted_data: encrypted,
            nonce: nonce_bytes.to_vec(),
            metadata: ShareMetadata {
                key_id: key_id.clone(),
                threshold: metadata.threshold as usize,
                total_shares: metadata.total_shares as usize,
                created_at: chrono::Utc::now(),
                expires_at: Some(chrono::Utc::now() + chrono::Duration::days(30)),
            },
        };

        // Store encrypted share
        let identifier = store_share(provider, env, &region, &encrypted_share).await?;

        locations.push(StorageLocation {
            provider,
            region,
            identifier,
        });
    }

    Ok(locations)
}

fn select_providers(metadata: &SecretMetadata) -> Vec<CloudProvider> {
    let mut providers = vec![
        CloudProvider::Aws,
        CloudProvider::Cloudflare,
        CloudProvider::Memory,
    ];

    // Distribute across multiple providers for resilience
    if metadata.regions.len() > 1 {
        providers.retain(|p| is_provider_compliant(*p, metadata));
    }

    providers
}

fn select_region(provider: CloudProvider, metadata: &SecretMetadata) -> Result<String> {
    // Select region based on metadata preferences
    let default_regions = match provider {
        CloudProvider::Aws => vec!["us-west-1", "eu-west-1", "ap-northeast-1"],
        CloudProvider::Cloudflare => vec!["westus", "eastus", "europe"],
        CloudProvider::Memory => vec!["local"],
    };

    // Use specified region if available, otherwise default
    for region in &metadata.regions {
        if default_regions.contains(&region.as_str()) {
            return Ok(region.clone());
        }
    }

    Ok(default_regions[0].to_string())
}

fn is_provider_compliant(provider: CloudProvider, metadata: &SecretMetadata) -> bool {
    // Check compliance requirements
    match provider {
        CloudProvider::Aws => {
            // Check if AWS regions meet compliance
            metadata
                .regions
                .iter()
                .any(|r| r.starts_with("us-") || r.starts_with("eu-"))
        }
        CloudProvider::Cloudflare => true, // Global CDN
        CloudProvider::Memory => metadata.regions.contains(&"local".to_string()),
    }
}

pub async fn store_share(
    provider: CloudProvider,
    env: &Env,
    region: &str,
    share: &EncryptedShare,
) -> Result<String> {
    let data = serde_json::to_vec(share).map_err(|e| {
        crate::error::MpcError::StorageError(format!("Serialization failed: {}", e))
    })?;

    let key = format!("shares/{}/{}", share.metadata.key_id, share.share_id);

    match provider {
        CloudProvider::Aws => aws::store(&key, &data, region).await,
        CloudProvider::Cloudflare => cloudflare::store(env, &key, &data).await,
        CloudProvider::Memory => memory::MemoryStorage::new().store(&key, &data).await,
    }
}

pub async fn retrieve_shares(
    provider: CloudProvider,
    env: &Env,
    key_id: &str,
) -> Result<Vec<EncryptedShare>> {
    let prefix = format!("shares/{}/", key_id);

    let keys = match provider {
        CloudProvider::Aws => aws::list_keys(&prefix).await?,
        CloudProvider::Cloudflare => cloudflare::list_keys(env, &prefix).await?,
        CloudProvider::Memory => memory::MemoryStorage::new().list_keys(&prefix).await?,
    };

    let mut shares = Vec::new();
    for key in keys {
        let data = match provider {
            CloudProvider::Aws => aws::retrieve(&key).await?,
            CloudProvider::Cloudflare => cloudflare::retrieve(env, &key).await?,
            CloudProvider::Memory => memory::MemoryStorage::new().retrieve(&key).await?,
        };

        // Parse first element if it's a Vec<String>
        let bytes = if !data.is_empty() {
            data[0].as_bytes().to_vec()
        } else {
            continue;
        };

        let share: EncryptedShare = serde_json::from_slice(&bytes).map_err(|e| {
            crate::error::MpcError::StorageError(format!("Deserialization failed: {}", e))
        })?;
        shares.push(share);
    }

    Ok(shares)
}
