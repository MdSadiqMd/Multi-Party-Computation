pub mod aws;
pub mod azure;
pub mod digital_ocean;

use crate::{error::Result, meta::*};

pub async fn distribute_shares(
    shares: Vec<Vec<u8>>,
    metadata: &SecretMetadata,
) -> Result<Vec<StorageLocation>> {
    let mut locations = Vec::new();
    let providers = select_providers(metadata);

    for (index, share) in shares.into_iter().enumerate() {
        let share_base64 = base64::encode(share);
        let provider = providers[index % providers.len()];

        let region = select_region(provider, metadata)?;
        let location = store_share(provider, region, share_base64).await?;

        locations.push(StorageLocation {
            provider: *provider,
            region,
            identifier: location,
        });
    }

    Ok(locations)
}

fn select_providers(metadata: &SecretMetadata) -> Vec<CloudProvider> {
    let mut providers = vec![
        CloudProvider::Aws,
        CloudProvider::DigitalOcean,
        CloudProvider::Azure,
    ];
    providers.retain(|p| is_provider_compliant(*p, metadata));
    providers
}

fn is_provider_compliant(provider: CloudProvider, metadata: &SecretMetadata) -> bool {
    // TODO: Implement region-based compliance checks
    true
}

async fn store_share(provider: CloudProvider, region: String, share: String) -> Result<String> {
    match provider {
        CloudProvider::Aws => aws::store(&region, &share).await,
        CloudProvider::DigitalOcean => digital_ocean::store(&region, &share).await,
        CloudProvider::Azure => azure::store(&region, &share).await,
    }
}
