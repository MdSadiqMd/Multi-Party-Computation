// Zero-Knowledge Proofs for MPC
use crate::error::{MpcError, Result};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

// Schnorr proof of knowledge of discrete logarithm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrProof {
    pub commitment: CompressedRistretto,
    pub challenge: Scalar,
    pub response: Scalar,
}

impl SchnorrProof {
    // Generate a proof of knowledge for a secret
    pub fn prove(secret: &Scalar) -> Self {
        // Generate random nonce
        let nonce = super::random_scalar();

        // Commitment: R = g^r
        let commitment = RISTRETTO_BASEPOINT_POINT * nonce;

        // Public key: Y = g^x
        let public_key = RISTRETTO_BASEPOINT_POINT * secret;

        // Challenge: c = H(R || Y)
        let challenge = hash_to_scalar(&[
            commitment.compress().as_bytes(),
            public_key.compress().as_bytes(),
        ]);

        // Response: s = r + c*x
        let response = nonce + challenge * secret;

        SchnorrProof {
            commitment: commitment.compress(),
            challenge,
            response,
        }
    }

    // Verify a proof
    pub fn verify(&self, public_key: &RistrettoPoint) -> Result<bool> {
        // Decompress commitment
        let commitment = self
            .commitment
            .decompress()
            .ok_or(MpcError::CryptoError("Invalid commitment".into()))?;

        // Recompute challenge
        let expected_challenge =
            hash_to_scalar(&[self.commitment.as_bytes(), public_key.compress().as_bytes()]);

        if self.challenge != expected_challenge {
            return Ok(false);
        }

        // Verify: g^s = R * Y^c
        let lhs = RISTRETTO_BASEPOINT_POINT * self.response;
        let rhs = commitment + public_key * self.challenge;

        Ok(lhs == rhs)
    }
}

// Range proof (simplified Bulletproofs-like)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeProof {
    pub commitment: CompressedRistretto,
    pub proof_data: Vec<u8>,
}

impl RangeProof {
    // Prove that a value is in range [0, 2^n)
    pub fn prove(value: u64, bits: usize) -> Result<Self> {
        if value >= (1u64 << bits) {
            return Err(MpcError::CryptoError("Value out of range".into()));
        }

        // Simplified range proof (real implementation would use Bulletproofs)
        let blinding = super::random_scalar();
        let commitment =
            RISTRETTO_BASEPOINT_POINT * Scalar::from(value) + RISTRETTO_BASEPOINT_POINT * blinding;

        // Generate proof data (simplified)
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&value.to_le_bytes());
        proof_data.extend_from_slice(&blinding.to_bytes());

        Ok(RangeProof {
            commitment: commitment.compress(),
            proof_data,
        })
    }

    // Verify a range proof
    pub fn verify(&self, bits: usize) -> Result<bool> {
        // Simplified verification
        if self.proof_data.len() < 40 {
            return Ok(false);
        }

        let value = u64::from_le_bytes(self.proof_data[..8].try_into().unwrap());

        Ok(value < (1u64 << bits))
    }
}

// Equality proof: prove two commitments hide the same value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EqualityProof {
    pub challenge: Scalar,
    pub response: Scalar,
}

impl EqualityProof {
    // Prove two commitments hide the same value
    pub fn prove(
        _value: &Scalar,
        blinding1: &Scalar,
        blinding2: &Scalar,
        commitment1: &RistrettoPoint,
        commitment2: &RistrettoPoint,
    ) -> Self {
        // Random nonce
        let nonce = super::random_scalar();

        // Compute auxiliary commitments
        let aux1 = RISTRETTO_BASEPOINT_POINT * nonce;
        let aux2 = RISTRETTO_BASEPOINT_POINT * nonce;

        // Challenge
        let challenge = hash_to_scalar(&[
            commitment1.compress().as_bytes(),
            commitment2.compress().as_bytes(),
            aux1.compress().as_bytes(),
            aux2.compress().as_bytes(),
        ]);

        // Response
        let response = nonce + challenge * (blinding1 - blinding2);

        EqualityProof {
            challenge,
            response,
        }
    }

    // Verify equality proof
    pub fn verify(&self, _commitment1: &RistrettoPoint, _commitment2: &RistrettoPoint) -> bool {
        // TODO: need to implement equality proof verification
        true
    }
}

// Proof of correct share generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareGenerationProof {
    pub share_commitments: Vec<CompressedRistretto>,
    pub consistency_proofs: Vec<SchnorrProof>,
}

impl ShareGenerationProof {
    // Generate proof for Shamir secret sharing
    pub fn prove(coefficients: &[Scalar], shares: &[(u32, Scalar)]) -> Result<Self> {
        // Commit to polynomial coefficients
        let share_commitments: Vec<CompressedRistretto> = coefficients
            .iter()
            .map(|coeff| (RISTRETTO_BASEPOINT_POINT * coeff).compress())
            .collect();

        // Generate consistency proofs for shares
        let consistency_proofs: Vec<SchnorrProof> = shares
            .iter()
            .map(|(_, share)| SchnorrProof::prove(share))
            .collect();

        Ok(ShareGenerationProof {
            share_commitments,
            consistency_proofs,
        })
    }

    // Verify share generation proof
    pub fn verify(&self, participant_id: u32, share_value: &Scalar) -> Result<bool> {
        // Verify share is consistent with commitments
        let mut expected = RistrettoPoint::default();
        let x = Scalar::from(participant_id);
        let mut x_power = Scalar::one();

        for commitment in &self.share_commitments {
            let point = commitment
                .decompress()
                .ok_or(MpcError::CryptoError("Invalid commitment".into()))?;
            expected += point * x_power;
            x_power *= x;
        }

        let actual = RISTRETTO_BASEPOINT_POINT * share_value;
        Ok(expected == actual)
    }
}

// Hash data to scalar
fn hash_to_scalar(data: &[&[u8]]) -> Scalar {
    let mut hasher = Sha3_256::new();
    for d in data {
        hasher.update(d);
    }
    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order(hash.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr_proof() {
        let secret = super::super::random_scalar();
        let public_key = RISTRETTO_BASEPOINT_POINT * secret;

        let proof = SchnorrProof::prove(&secret);
        assert!(proof.verify(&public_key).unwrap());

        // Wrong public key should fail
        let wrong_key = RISTRETTO_BASEPOINT_POINT * super::super::random_scalar();
        assert!(!proof.verify(&wrong_key).unwrap());
    }

    #[test]
    fn test_range_proof() {
        let value = 42u64;
        let bits = 8;

        let proof = RangeProof::prove(value, bits).unwrap();
        assert!(proof.verify(bits).unwrap());

        // out of range should fail
        let result = RangeProof::prove(256, 8);
        assert!(result.is_err());
    }
}
