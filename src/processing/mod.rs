pub mod shamir;

use crate::{
    crypto::{mpc::*, shamir::ShamirSecretSharing, threshold_signatures::*},
    error::{MpcError, Result},
    meta::{metadata::CloudProvider, *},
    storage,
};
use ed25519_dalek::{PublicKey as VerifyingKey, Signature as Ed25519Signature, Verifier};
use sha3::{Digest, Sha3_256};
use worker::Env;

/// Process and distribute shares using enhanced Shamir Secret Sharing
pub async fn distribute_shares(env: &Env, request: UserRequest) -> Result<Vec<StorageLocation>> {
    // Validate signature first
    validate_signature(&request)?;

    // Use enhanced Shamir with large prime
    let sss = ShamirSecretSharing::new(
        request.metadata.threshold as usize,
        request.metadata.total_shares as usize,
    )?;

    let shares = sss.split_secret(request.encrypted_private_key.as_bytes())?;

    // Convert to raw bytes for storage
    let share_bytes: Vec<Vec<u8>> = shares
        .into_iter()
        .map(|s| serde_json::to_vec(&s).unwrap())
        .collect();

    let locations = storage::distribute_shares(env, share_bytes, &request.metadata).await?;
    Ok(locations)
}

/// Validate Ed25519 signature
pub fn validate_signature(request: &UserRequest) -> Result<()> {
    // Parse public key
    let pubkey_bytes = bs58::decode(&request.user_pubkey)
        .into_vec()
        .map_err(|e| MpcError::CryptoError(format!("Invalid public key encoding: {}", e)))?;

    if pubkey_bytes.len() != 32 {
        return Err(MpcError::CryptoError("Invalid public key length".into()));
    }

    let mut pubkey_array = [0u8; 32];
    pubkey_array.copy_from_slice(&pubkey_bytes);
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|e| MpcError::CryptoError(format!("Invalid public key: {}", e)))?;

    // Parse signature
    let sig_bytes = bs58::decode(&request.signature)
        .into_vec()
        .map_err(|e| MpcError::CryptoError(format!("Invalid signature encoding: {}", e)))?;

    if sig_bytes.len() != 64 {
        return Err(MpcError::CryptoError("Invalid signature length".into()));
    }

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);
    let signature = Ed25519Signature::from_bytes(&sig_array)
        .map_err(|e| MpcError::CryptoError(format!("Invalid signature: {}", e)))?;

    // Create message to verify
    let mut hasher = Sha3_256::new();
    hasher.update(&request.encrypted_private_key);
    hasher.update(serde_json::to_vec(&request.metadata).unwrap());
    let message = hasher.finalize();

    // Verify signature
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| MpcError::CryptoError("Signature verification failed".into()))?;

    Ok(())
}

/// Retrieve and decrypt shares
pub async fn retrieve_shares(env: &Env, key_id: &str) -> Result<Vec<String>> {
    // Retrieve encrypted shares from storage
    let encrypted_shares = storage::retrieve_shares(CloudProvider::Cloudflare, env, key_id).await?;

    // Decrypt shares (in production, use proper key management)
    let mut decrypted_shares = Vec::new();
    for encrypted in encrypted_shares {
        // For now, return the encrypted data as base64
        // In production, decrypt with proper key
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &encrypted.encrypted_data,
        );
        decrypted_shares.push(encoded);
    }

    Ok(decrypted_shares)
}

/// Sign transaction using threshold signatures
pub async fn threshold_sign_transaction(
    participants: Vec<MpcParticipant>,
    message: &[u8],
) -> Result<(
    curve25519_dalek::ristretto::CompressedRistretto,
    curve25519_dalek::scalar::Scalar,
)> {
    if participants.len() < 2 {
        return Err(MpcError::CryptoError("Not enough participants".into()));
    }

    // This is a simplified version - real implementation would coordinate between participants
    let _coordinator = SigningCoordinator::new(2, message);

    // In production, this would involve network communication between participants
    // For now, return a placeholder
    Err(MpcError::CryptoError(
        "Threshold signing not yet implemented".into(),
    ))
}

/// Sign Solana transaction (blockchain features disabled)
#[allow(unused_variables)]
pub async fn solana_sign(_request: TransactionRequest) -> Result<String> {
    Err(MpcError::CryptoError(
        "Blockchain feature not available. Create a separate crate for blockchain integration."
            .into(),
    ))
}
