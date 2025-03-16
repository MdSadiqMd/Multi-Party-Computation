pub mod shamir;
pub mod solana;
use crate::{error::Result, meta::*, storage};
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

pub async fn solana_sign(request: TransactionRequest) -> Result<String> {
    solana::sign_transaction(
        &request.sender,
        &request.receiver,
        request.amount,
        &request.recent_blockhash,
    )
}
