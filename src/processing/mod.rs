pub mod shamir;
pub mod solana;

use crate::{error::Result, models::*};

pub async fn distribute_shares(request: UserRequest) -> Result<Vec<StorageLocation>> {
    let shares = shamir::split_secret(
        request.encrypted_private_key.as_bytes(),
        request.metadata.threshold,
        request.metadata.total_shares,
    )?;

    let locations = storage::distribute_shares(shares, &request.metadata).await?;
    Ok(locations)
}

pub async fn solana_send_transaction(request: TransactionRequest) -> Result<String> {
    solana::send_transaction(
        &request.sender,
        &request.receiver,
        request.amount,
        &request.recent_blockhash,
    )
}

pub async fn solana_sign(request: TransactionRequest) -> Result<String> {
    solana::sign_transaction(
        &request.sender,
        &request.receiver,
        request.amount,
        &request.recent_blockhash,
    )
}
