use crate::error::Result;
use threshold_secret_sharing::tss::ThresholdSecretSharing;

pub fn split_secret(secret: &[u8], threshold: u8, total_shares: u8) -> Result<Vec<Vec<u8>>> {
    if threshold < 1 || total_shares < threshold {
        return Err(MpcError::InvalidMetadata);
    }

    let tss = ThresholdSecretSharing::new(threshold as usize);
    Ok(tss.split(secret, total_shares as usize))
}

pub fn combine_shares(shares: &[Vec<u8>]) -> Result<Vec<u8>> {
    if shares.is_empty() {
        return Err(MpcError::CryptoError("No shares provided".into()));
    }

    let tss = ThresholdSecretSharing::new(shares.len());
    Ok(tss.reconstruct(shares))
}
