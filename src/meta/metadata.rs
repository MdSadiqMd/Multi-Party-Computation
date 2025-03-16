use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRequest {
    pub user_pubkey: String,
    pub encrypted_private_key: String,
    pub metadata: SecretMetadata,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub threshold: u8,
    pub total_shares: u8,
    pub regions: Vec<String>,
    pub key_version: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionRequest {
    pub sender: String,
    pub receiver: String,
    pub amount: u64,
    pub recent_blockhash: String,
    pub secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StorageLocation {
    pub provider: CloudProvider,
    pub region: String,
    pub identifier: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum CloudProvider {
    Aws,
    Cloudflare,
    Memory,
}
