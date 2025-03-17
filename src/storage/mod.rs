pub mod aws;
pub mod cloudflare;
pub mod memory;
use crate::{
    error::Result,
    meta::{metadata::CloudProvider, metadata::SecretMetadata, StorageLocation},
};
use worker::Env;

pub async fn distribute_shares(
    env: &Env,
    shares: Vec<Vec<u8>>,
    metadata: &SecretMetadata,
) -> Result<Vec<StorageLocation>> {
    let mut locations = Vec::new();
    let providers = select_providers(metadata);

    for (index, share) in shares.into_iter().enumerate() {
        let share_base64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, share);
        let provider = providers[index % providers.len()];

        let region = select_region(provider, metadata)?;
        let stored_shares = store_share(provider, env, region.clone(), share_base64).await?;

        for stored_share in stored_shares {
            locations.push(StorageLocation {
                provider,
                region: region.clone(),
                identifier: stored_share,
            });
        }
    }

    Ok(locations)
}

fn select_providers(metadata: &SecretMetadata) -> Vec<CloudProvider> {
    let mut providers = vec![
        CloudProvider::Aws,
        CloudProvider::Cloudflare,
        CloudProvider::Memory,
    ];
    providers.retain(|p| is_provider_compliant(*p, metadata));
    providers
}

fn select_region(provider: CloudProvider, _metadata: &SecretMetadata) -> Result<String> {
    // TODO: Make it generic
    match provider {
        CloudProvider::Aws => Ok("us-west-1".to_string()),
        CloudProvider::Cloudflare => Ok("westus".to_string()),
        CloudProvider::Memory => Ok("nyc3".to_string()),
    }
}

fn is_provider_compliant(_provider: CloudProvider, _metadata: &SecretMetadata) -> bool {
    // TODO: Implement region-based compliance checks
    true
}

pub async fn store_share(
    provider: CloudProvider,
    env: &Env,
    region: String,
    _share: String,
) -> Result<Vec<String>> {
    match provider {
        CloudProvider::Aws => aws::retrieve(&region).await,
        CloudProvider::Cloudflare => cloudflare::retrieve(env, &region).await,
        CloudProvider::Memory => memory::MemoryStorage::new().retrieve(&region).await,
    }
}
