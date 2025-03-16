use crate::error::{MpcError, Result};
use std::convert::TryInto;
use threshold_secret_sharing::shamir::ShamirSecretSharing;

pub fn split_secret(
    secret: &[u8],
    threshold: u8,
    total_shares: u8,
    prime: i64,
) -> Result<Vec<Vec<u8>>> {
    if threshold < 1 || total_shares < threshold {
        return Err(MpcError::InvalidMetadata);
    }

    let tss = ShamirSecretSharing {
        threshold: threshold as usize,
        share_count: total_shares as usize,
        prime,
    };

    let secret_num = i64::from_be_bytes(secret.try_into().map_err(|_| MpcError::InvalidSecret)?);

    if secret_num >= prime {
        return Err(MpcError::InvalidSecret);
    }

    let shares = tss.share(secret_num);
    Ok((1..=total_shares as i64)
        .zip(shares.into_iter())
        .map(|(x, y)| [x.to_be_bytes(), y.to_be_bytes()].concat())
        .collect())
}

pub fn combine_shares(shares: &[Vec<u8>], threshold: u8, prime: i64) -> Result<Vec<u8>> {
    if shares.is_empty() {
        return Err(MpcError::CryptoError("No shares provided".into()));
    }

    let mut x_coords = Vec::with_capacity(shares.len());
    let mut y_coords = Vec::with_capacity(shares.len());

    for share in shares {
        if share.len() != 16 {
            return Err(MpcError::InvalidShare);
        }

        let x = i64::from_be_bytes(share[0..8].try_into().unwrap());
        let y = i64::from_be_bytes(share[8..16].try_into().unwrap());

        let x_usize = usize::try_from(x).map_err(|_| MpcError::InvalidShare)?;

        x_coords.push(x_usize);
        y_coords.push(y);
    }

    let tss = ShamirSecretSharing {
        threshold: threshold as usize,
        share_count: shares.len(),
        prime,
    };

    let secret = tss.reconstruct(&x_coords, &y_coords);
    Ok(secret.to_be_bytes().to_vec())
}
