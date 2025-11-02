// Threshold Signature Scheme (TSS) Implementation
// Implements threshold ECDSA and EdDSA signatures
use crate::error::{MpcError, Result};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use ed25519_dalek::{PublicKey as VerifyingKey, SecretKey as SigningKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use zeroize::Zeroizing;

// Threshold signature share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureShare {
    pub participant_id: u32,
    pub share: Scalar,
    pub commitment: CompressedRistretto,
    pub message_hash: [u8; 32],
}

// Partial signature from a participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSignature {
    pub participant_id: u32,
    pub r: CompressedRistretto,
    pub s: Scalar,
}

// Threshold signature protocol
#[derive(Debug)]
pub struct ThresholdSignature {
    pub threshold: usize,
    pub participant_id: u32,
    secret_share: Scalar,
    pub public_key: RistrettoPoint,
    pub public_shares: HashMap<u32, RistrettoPoint>,
    nonce_shares: HashMap<[u8; 32], Scalar>,
    nonce_commitments: HashMap<[u8; 32], CompressedRistretto>,
}

impl ThresholdSignature {
    // Create a new threshold signature instance
    pub fn new(
        threshold: usize,
        participant_id: u32,
        secret_share: Scalar,
        public_key: RistrettoPoint,
        public_shares: HashMap<u32, RistrettoPoint>,
    ) -> Self {
        ThresholdSignature {
            threshold,
            participant_id,
            secret_share,
            public_key,
            public_shares,
            nonce_shares: HashMap::new(),
            nonce_commitments: HashMap::new(),
        }
    }

    // Phase 1: Generate nonce commitment for signing
    pub fn generate_nonce_commitment(&mut self, message: &[u8]) -> Result<CompressedRistretto> {
        let message_hash = hash_message(message);

        // Generate random nonce
        let nonce = super::random_scalar();
        let commitment = (RISTRETTO_BASEPOINT_POINT * &nonce).compress();

        // Store for later use
        self.nonce_shares.insert(message_hash, nonce);
        self.nonce_commitments.insert(message_hash, commitment);

        Ok(commitment)
    }

    // Phase 2: Generate partial signature
    pub fn sign_partial(
        &self,
        message: &[u8],
        aggregated_nonce: RistrettoPoint,
    ) -> Result<PartialSignature> {
        let message_hash = hash_message(message);

        // Retrieve nonce
        let nonce = self
            .nonce_shares
            .get(&message_hash)
            .ok_or(MpcError::CryptoError("Nonce not found".into()))?;

        // Compute challenge
        let challenge = compute_challenge(&aggregated_nonce, &self.public_key, message);

        // Compute partial signature: s_i = k_i + c * sk_i
        let s = nonce + challenge * &self.secret_share;

        Ok(PartialSignature {
            participant_id: self.participant_id,
            r: aggregated_nonce.compress(),
            s,
        })
    }

    // Combine partial signatures into final signature
    pub fn combine_signatures(
        &self,
        partial_sigs: Vec<PartialSignature>,
        participants: &[u32],
    ) -> Result<(CompressedRistretto, Scalar)> {
        if partial_sigs.len() < self.threshold {
            return Err(MpcError::CryptoError(format!(
                "Not enough signatures: {} < {}",
                partial_sigs.len(),
                self.threshold
            )));
        }

        // All partial signatures should have the same R
        let r = partial_sigs[0].r;
        for sig in &partial_sigs[1..] {
            if sig.r != r {
                return Err(MpcError::CryptoError("Inconsistent R values".into()));
            }
        }

        // Compute Lagrange coefficients
        let coefficients = compute_lagrange_coefficients(participants);

        // Combine partial signatures: s = Σ λ_i * s_i
        let mut combined_s = Scalar::zero();
        for (sig, coeff) in partial_sigs.iter().zip(coefficients.iter()) {
            combined_s += sig.s * coeff;
        }

        Ok((r, combined_s))
    }

    // Verify a threshold signature
    pub fn verify(
        public_key: &RistrettoPoint,
        message: &[u8],
        signature: &(CompressedRistretto, Scalar),
    ) -> Result<bool> {
        let (r, s) = signature;

        // Decompress R
        let r_point = r
            .decompress()
            .ok_or(MpcError::CryptoError("Invalid R point".into()))?;

        // Compute challenge
        let challenge = compute_challenge(&r_point, public_key, message);

        // Verify: s*G = R + c*PK
        let s_base = RISTRETTO_BASEPOINT_POINT * s;
        let verification = r_point + public_key * challenge;

        Ok(s_base == verification)
    }
}

// Compute Lagrange coefficients for threshold reconstruction
fn compute_lagrange_coefficients(participants: &[u32]) -> Vec<Scalar> {
    participants
        .iter()
        .map(|&i| {
            let mut num = Scalar::one();
            let mut den = Scalar::one();

            for &j in participants {
                if i != j {
                    num *= Scalar::from(j);
                    den *= Scalar::from(j) - Scalar::from(i);
                }
            }

            num * den.invert()
        })
        .collect()
}

// Hash a message for signing
fn hash_message(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(message);
    hasher.finalize().into()
}

// Compute signature challenge (Fiat-Shamir)
fn compute_challenge(r: &RistrettoPoint, public_key: &RistrettoPoint, message: &[u8]) -> Scalar {
    let mut hasher = Sha3_256::new();
    hasher.update(r.compress().as_bytes());
    hasher.update(public_key.compress().as_bytes());
    hasher.update(message);

    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order(hash.into())
}

// Threshold EdDSA signature scheme
pub struct ThresholdEd25519 {
    _threshold: usize,
    participant_id: u32,
    signing_key_share: Zeroizing<[u8; 32]>,
    _group_verifying_key: VerifyingKey,
}

impl ThresholdEd25519 {
    // Create from DKG output
    pub fn from_dkg(
        threshold: usize,
        participant_id: u32,
        secret_share: &Scalar,
        group_public_key: &RistrettoPoint,
    ) -> Result<Self> {
        // Convert scalar to bytes
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&secret_share.to_bytes());

        // Convert group public key to Ed25519 verifying key
        let pk_bytes = group_public_key.compress().to_bytes();
        let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| MpcError::CryptoError(format!("Invalid public key: {}", e)))?;

        Ok(ThresholdEd25519 {
            _threshold: threshold,
            participant_id,
            signing_key_share: Zeroizing::new(key_bytes),
            _group_verifying_key: verifying_key,
        })
    }

    // Generate a partial Ed25519 signature
    pub fn sign_partial(&self, message: &[u8]) -> Result<PartialEd25519Signature> {
        // simplified - real implementation would use preprocessing
        let signing_key = SigningKey::from_bytes(self.signing_key_share.as_ref())
            .map_err(|e| MpcError::CryptoError(format!("Invalid signing key: {}", e)))?;

        // expanded secret key and sign
        let expanded_signing_key = ed25519_dalek::ExpandedSecretKey::from(&signing_key);
        let public_key = ed25519_dalek::PublicKey::from(&signing_key);
        let signature = expanded_signing_key.sign(message, &public_key);

        Ok(PartialEd25519Signature {
            participant_id: self.participant_id,
            signature: signature.to_bytes(),
        })
    }
}

// Partial Ed25519 signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialEd25519Signature {
    pub participant_id: u32,
    #[serde(with = "serde_big_array::BigArray")]
    pub signature: [u8; 64],
}

// MPC signing coordinator
pub struct SigningCoordinator {
    pub threshold: usize,
    pub message_hash: [u8; 32],
    nonce_commitments: HashMap<u32, CompressedRistretto>,
    partial_signatures: HashMap<u32, PartialSignature>,
}

impl SigningCoordinator {
    pub fn new(threshold: usize, message: &[u8]) -> Self {
        SigningCoordinator {
            threshold,
            message_hash: hash_message(message),
            nonce_commitments: HashMap::new(),
            partial_signatures: HashMap::new(),
        }
    }

    // Add nonce commitment from participant
    pub fn add_nonce_commitment(&mut self, participant_id: u32, commitment: CompressedRistretto) {
        self.nonce_commitments.insert(participant_id, commitment);
    }

    // Check if we have enough commitments
    pub fn has_enough_commitments(&self) -> bool {
        self.nonce_commitments.len() >= self.threshold
    }

    // Aggregate nonce commitments
    pub fn aggregate_nonces(&self) -> Result<RistrettoPoint> {
        let mut aggregated = RistrettoPoint::default();

        for commitment in self.nonce_commitments.values() {
            let point = commitment
                .decompress()
                .ok_or(MpcError::CryptoError("Invalid nonce commitment".into()))?;
            aggregated += point;
        }

        Ok(aggregated)
    }

    // Add partial signature
    pub fn add_partial_signature(&mut self, signature: PartialSignature) {
        self.partial_signatures
            .insert(signature.participant_id, signature);
    }

    // Check if we have enough signatures
    pub fn has_enough_signatures(&self) -> bool {
        self.partial_signatures.len() >= self.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_signature() {
        let threshold = 2;
        let message = b"test message";

        // Setup keys (normally from DKG) - use Lagrange interpolation approach
        let secret1 = super::super::random_scalar();
        let secret2 = super::super::random_scalar();

        // Compute public key shares
        let pk1 = RISTRETTO_BASEPOINT_POINT * secret1;
        let pk2 = RISTRETTO_BASEPOINT_POINT * secret2;

        // For 2-of-2 threshold, compute group public key with Lagrange coefficients
        // L_1(0) = 2/(2-1) = 2, L_2(0) = 1/(1-2) = -1
        // But for simplicity in a 2-of-2, we can use direct aggregation
        let lambda1 = Scalar::from(2u32);
        let lambda2 = -Scalar::one();
        let public_key = pk1 * lambda1 + pk2 * lambda2;

        let mut public_shares = HashMap::new();
        public_shares.insert(1, pk1);
        public_shares.insert(2, pk2);

        // Create signers
        let mut signer1 =
            ThresholdSignature::new(threshold, 1, secret1, public_key, public_shares.clone());

        let mut signer2 = ThresholdSignature::new(threshold, 2, secret2, public_key, public_shares);

        // Phase 1: Generate nonces
        let nonce1 = signer1.generate_nonce_commitment(message).unwrap();
        let nonce2 = signer2.generate_nonce_commitment(message).unwrap();

        // Aggregate nonces with Lagrange coefficients
        let r1 = nonce1.decompress().unwrap();
        let r2 = nonce2.decompress().unwrap();
        let agg_nonce = r1 * lambda1 + r2 * lambda2;

        // Phase 2: Sign
        let partial1 = signer1.sign_partial(message, agg_nonce).unwrap();
        let partial2 = signer2.sign_partial(message, agg_nonce).unwrap();

        // Combine signatures
        let signature = signer1
            .combine_signatures(vec![partial1, partial2], &[1, 2])
            .unwrap();

        // Verify
        let valid = ThresholdSignature::verify(&public_key, message, &signature).unwrap();
        assert!(valid);
    }
}
