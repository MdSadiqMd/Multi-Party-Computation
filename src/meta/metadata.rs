use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub key_fingerprint: String,
    pub threshold: u8,
    pub total_shares: u8,
    pub avoid_countries: Vec<String>,
    pub preferred_countries: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretRequest {
    pub encrypted_secret: String,
    pub metadata: SecretMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StorageLocation {
    pub cloud_provider: CloudProvider,
    pub region: String,
    pub secret_share: String,
    pub share_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum CloudProvider {
    Aws,
    DigitalOcean,
    Azure,
}
