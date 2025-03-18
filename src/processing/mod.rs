pub mod shamir;
pub mod solana;

use crate::{aws, cloudflare, error::Result, memory, meta::*, storage, MpcError};
use sha2::{Digest, Sha256};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use std::str::FromStr;
use worker::Env;

const PRIME: i64 = 257;
pub async fn distribute_shares(env: &Env, request: UserRequest) -> Result<Vec<StorageLocation>> {
    let shares = shamir::split_secret(
        request.encrypted_private_key.as_bytes(),
        request.metadata.threshold,
        request.metadata.total_shares,
        PRIME,
    )?;

    let locations = storage::distribute_shares(env, shares, &request.metadata).await?;
    Ok(locations)
}

pub fn validate_signature(request: &UserRequest) -> Result<()> {
    let pubkey = Pubkey::from_str(&request.user_pubkey)
        .map_err(|e| MpcError::CryptoError(format!("Invalid public key: {}", e)))?;

    let signature = Signature::from_str(&request.signature)
        .map_err(|e| MpcError::CryptoError(format!("Invalid signature: {}", e)))?;

    let mut hasher = Sha256::new();
    hasher.update(&request.encrypted_private_key);
    hasher.update(serde_json::to_vec(&request.metadata)?);
    let message_hash = hasher.finalize();

    if !signature.verify(&pubkey.to_bytes(), &message_hash) {
        return Err(MpcError::CryptoError("Invalid signature".into()));
    }

    Ok(())
}

pub async fn retrieve_shares(env: &Env, pubkey: &str) -> Result<Vec<String>> {
    let mut shares = Vec::new();

    if let Ok(aws_shares) = aws::retrieve(pubkey).await {
        shares.extend(aws_shares);
    }

    if let Ok(cf_shares) = cloudflare::retrieve(env, pubkey).await {
        shares.extend(cf_shares);
    }

    let memory_storage = memory::MemoryStorage::new();
    if let Ok(mem_shares) = memory_storage.retrieve(pubkey).await {
        shares.extend(mem_shares);
    }

    if shares.is_empty() {
        return Err(MpcError::StorageError(
            "No shares found for the given public key".into(),
        ));
    }

    Ok(shares)
}

pub async fn solana_sign(request: TransactionRequest) -> Result<String> {
    solana::sign_transaction(
        &request.sender,
        &request.receiver,
        request.amount,
        &request.recent_blockhash,
    )
}
