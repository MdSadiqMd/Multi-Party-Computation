pub mod shamir;
pub mod solana;

use crate::{
    error::{MpcError, Result},
    meta::*,
    storage,
};
use sha2::{Digest, Sha256};
use solana_sdk::{pubkey::Pubkey, signature::Signature};
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
    hasher.update(serde_json::to_vec(&request.metadata).unwrap());
    let message_hash = hasher.finalize();

    if !signature.verify(pubkey.as_ref(), &message_hash) {
        return Err(MpcError::CryptoError("Invalid signature".into()));
    }

    Ok(())
}

pub async fn retrieve_shares(env: &Env, pubkey: &str) -> Result<Vec<String>> {
    let bucket = env.bucket("SHARES_BUCKET")?;
    let list = bucket
        .list()
        .prefix(&format!("shares/{}/", pubkey))
        .execute()
        .await?;

    let mut shares = Vec::new();
    for object in list.objects() {
        let value = bucket
            .get(object.key())
            .execute()
            .await?
            .ok_or(MpcError::StorageError("Missing object".into()))?;

        let body = value
            .body()
            .ok_or(MpcError::StorageError("Missing body".into()))?;
        let bytes = body.bytes().await?;
        let text = String::from_utf8(bytes)?;
        shares.push(text);
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
