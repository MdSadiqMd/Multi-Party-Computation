use crate::error::{MpcError, Result};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{
    dkg::{DkgCoordinator, DkgProtocol, DkgShare},
    shamir::{SecretShare, ShamirSecretSharing},
    threshold_signatures::{SignatureShare, ThresholdSignature},
};

// MPC protocol phase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MpcPhase {
    Initialization,
    KeyGeneration,
    Signing,
    Resharing,
    Recovery,
}

// mpc participant state
pub struct MpcParticipant {
    pub id: u32,
    pub threshold: usize,
    pub total_participants: usize,
    phase: MpcPhase,
    dkg_protocol: Option<DkgProtocol>,
    threshold_signer: Option<ThresholdSignature>,
    secret_shares: HashMap<String, SecretShare>,
    public_key: Option<RistrettoPoint>,
}

impl MpcParticipant {
    pub fn new(id: u32, threshold: usize, total_participants: usize) -> Result<Self> {
        if threshold > total_participants || threshold < 1 {
            return Err(MpcError::InvalidMetadata);
        }

        Ok(MpcParticipant {
            id,
            threshold,
            total_participants,
            phase: MpcPhase::Initialization,
            dkg_protocol: None,
            threshold_signer: None,
            secret_shares: HashMap::new(),
            public_key: None,
        })
    }

    // Initialize DKG protocol
    pub fn start_dkg(&mut self) -> Result<Vec<DkgShare>> {
        if self.phase != MpcPhase::Initialization {
            return Err(MpcError::CryptoError("Invalid phase for DKG".into()));
        }

        let mut dkg = DkgProtocol::new(self.id, self.threshold, self.total_participants)?;
        let shares = dkg.generate_shares()?;

        self.dkg_protocol = Some(dkg);
        self.phase = MpcPhase::KeyGeneration;

        Ok(shares)
    }

    // Process DKG share from another participant
    pub fn process_dkg_share(&mut self, share: DkgShare) -> Result<()> {
        if self.phase != MpcPhase::KeyGeneration {
            return Err(MpcError::CryptoError("Not in key generation phase".into()));
        }

        let dkg = self
            .dkg_protocol
            .as_mut()
            .ok_or(MpcError::CryptoError("DKG not initialized".into()))?;

        dkg.process_share(share)?;
        Ok(())
    }

    // Finalize DKG and derive signing key
    pub fn finalize_dkg(&mut self) -> Result<RistrettoPoint> {
        if self.phase != MpcPhase::KeyGeneration {
            return Err(MpcError::CryptoError("Not in key generation phase".into()));
        }

        let dkg = self
            .dkg_protocol
            .as_mut()
            .ok_or(MpcError::CryptoError("DKG not initialized".into()))?;

        let (secret_share, group_public_key) = dkg.finalize()?;

        // Setup threshold signer
        self.threshold_signer = Some(ThresholdSignature::new(
            self.threshold,
            self.id,
            secret_share,
            group_public_key,
            dkg.public_key_shares.clone(),
        ));

        self.public_key = Some(group_public_key);
        self.phase = MpcPhase::Signing;

        Ok(group_public_key)
    }

    // Store a secret using Shamir Secret Sharing
    pub fn store_secret(&mut self, key: String, secret: &[u8]) -> Result<Vec<SecretShare>> {
        let sss = ShamirSecretSharing::new(self.threshold, self.total_participants)?;
        let shares = sss.split_secret(secret)?;

        // Store own share
        let own_share = shares
            .iter()
            .find(|s| s.index == self.id)
            .ok_or(MpcError::CryptoError("Own share not found".into()))?
            .clone();

        self.secret_shares.insert(key, own_share);

        Ok(shares)
    }

    // Recover a secret from shares
    pub fn recover_secret(&self, key: &str, shares: Vec<SecretShare>) -> Result<Vec<u8>> {
        // Get own share if available
        let mut all_shares = shares;
        if let Some(own_share) = self.secret_shares.get(key) {
            all_shares.push(own_share.clone());
        }

        // Extract the prime from one of the shares to ensure consistency
        if all_shares.is_empty() {
            return Err(MpcError::CryptoError("No shares provided".into()));
        }

        let prime = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &all_shares[0].prime);
        let sss = ShamirSecretSharing::with_prime(self.threshold, self.total_participants, prime)?;
        sss.combine_shares(&all_shares)
    }
}

// MPC message types for communication between participants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MpcMessage {
    DkgShare(DkgShare),
    NonceCommitment {
        participant_id: u32,
        commitment: CompressedRistretto,
        session_id: [u8; 32],
    },
    PartialSignature {
        participant_id: u32,
        signature: SignatureShare,
        session_id: [u8; 32],
    },
    SecretShare {
        key: String,
        share: SecretShare,
    },
    PublicKeyAnnouncement {
        participant_id: u32,
        public_key: CompressedRistretto,
    },
}

// MPC session coordinator (can be distributed)
pub struct MpcCoordinator {
    pub session_id: [u8; 32],
    pub threshold: usize,
    pub total_participants: usize,
    participants: HashMap<u32, ParticipantInfo>,
    dkg_coordinator: Option<DkgCoordinator>,
    phase: MpcPhase,
}

#[derive(Debug, Clone)]
struct ParticipantInfo {
    _id: u32,
    _public_key: Option<CompressedRistretto>,
    _online: bool,
}

impl MpcCoordinator {
    pub fn new(threshold: usize, total_participants: usize) -> Result<Self> {
        let session_id =
            super::hash(&format!("session-{}", chrono::Utc::now().timestamp()).as_bytes());

        Ok(MpcCoordinator {
            session_id,
            threshold,
            total_participants,
            participants: HashMap::new(),
            dkg_coordinator: None,
            phase: MpcPhase::Initialization,
        })
    }

    // Register a participant
    pub fn register_participant(&mut self, id: u32) -> Result<()> {
        if self.participants.len() >= self.total_participants {
            return Err(MpcError::CryptoError("Too many participants".into()));
        }

        self.participants.insert(
            id,
            ParticipantInfo {
                _id: id,
                _public_key: None,
                _online: true,
            },
        );

        Ok(())
    }

    // Check if ready to start DKG
    pub fn is_ready_for_dkg(&self) -> bool {
        self.participants.len() == self.total_participants && self.phase == MpcPhase::Initialization
    }

    // Start DKG phase
    pub fn start_dkg(&mut self) -> Result<()> {
        if !self.is_ready_for_dkg() {
            return Err(MpcError::CryptoError("Not ready for DKG".into()));
        }

        self.dkg_coordinator = Some(DkgCoordinator::new(
            self.threshold,
            self.total_participants,
        )?);

        self.phase = MpcPhase::KeyGeneration;
        Ok(())
    }
}

// Secure computation protocol for arbitrary functions
pub struct SecureComputation {
    participants: Vec<MpcParticipant>,
    inputs: HashMap<u32, Vec<u8>>,
    outputs: HashMap<u32, Vec<u8>>,
}

impl SecureComputation {
    // Create a new secure computation session
    pub fn new(participant_ids: Vec<u32>, threshold: usize) -> Result<Self> {
        let total = participant_ids.len();
        let participants = participant_ids
            .into_iter()
            .map(|id| MpcParticipant::new(id, threshold, total))
            .collect::<Result<Vec<_>>>()?;

        Ok(SecureComputation {
            participants,
            inputs: HashMap::new(),
            outputs: HashMap::new(),
        })
    }

    // Add input from a participant
    pub fn add_input(&mut self, participant_id: u32, input: Vec<u8>) -> Result<()> {
        self.inputs.insert(participant_id, input);
        Ok(())
    }

    // Execute secure computation (simplified example)
    pub fn compute<F>(&mut self, computation: F) -> Result<HashMap<u32, Vec<u8>>>
    where
        F: Fn(&[Vec<u8>]) -> Result<Vec<u8>>,
    {
        let inputs: Vec<Vec<u8>> = self.inputs.values().cloned().collect();

        // Execute computation (in real implementation, this would be done via MPC)
        let result = computation(&inputs)?;

        // Distribute results
        for participant in &self.participants {
            self.outputs.insert(participant.id, result.clone());
        }

        Ok(self.outputs.clone())
    }
}

// Proactive secret sharing for key refresh
pub struct ProactiveSecretSharing {
    threshold: usize,
    total_participants: usize,
    refresh_period: std::time::Duration,
    last_refresh: std::time::Instant,
}

impl ProactiveSecretSharing {
    pub fn new(threshold: usize, total_participants: usize) -> Self {
        ProactiveSecretSharing {
            threshold,
            total_participants,
            refresh_period: std::time::Duration::from_secs(86400), // Daily refresh
            last_refresh: std::time::Instant::now(),
        }
    }

    // Check if refresh is needed
    pub fn needs_refresh(&self) -> bool {
        self.last_refresh.elapsed() > self.refresh_period
    }

    // Generate refresh shares
    pub fn generate_refresh_shares(&mut self) -> Result<Vec<SecretShare>> {
        // Generate zero-sum shares for refresh
        let zero_secret = vec![0u8; 32];
        let sss = ShamirSecretSharing::new(self.threshold, self.total_participants)?;
        let refresh_shares = sss.split_secret(&zero_secret)?;

        self.last_refresh = std::time::Instant::now();
        Ok(refresh_shares)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpc_participant_lifecycle() {
        let threshold = 2;
        let total = 3;

        // Create participants
        let mut participants: Vec<MpcParticipant> = (1..=total)
            .map(|id| MpcParticipant::new(id as u32, threshold, total).unwrap())
            .collect();

        // Start DKG
        let mut all_shares = Vec::new();
        for participant in &mut participants {
            let shares = participant.start_dkg().unwrap();
            all_shares.push(shares);
        }

        // Distribute shares
        for (i, shares) in all_shares.iter().enumerate() {
            for share in shares {
                let to_idx = (share.to - 1) as usize;
                if to_idx != i {
                    participants[to_idx]
                        .process_dkg_share(share.clone())
                        .unwrap();
                }
            }
        }

        // Finalize DKG
        let mut group_keys = Vec::new();
        for participant in &mut participants {
            let key = participant.finalize_dkg().unwrap();
            group_keys.push(key);
        }

        // Verify all have same group key
        for i in 1..group_keys.len() {
            assert_eq!(group_keys[0], group_keys[i]);
        }
    }

    #[test]
    fn test_secret_sharing() {
        let mut participant = MpcParticipant::new(1, 2, 3).unwrap();
        let secret = b"test secret";

        let shares = participant
            .store_secret("test_key".to_string(), secret)
            .unwrap();
        assert_eq!(shares.len(), 3);

        // Recover with threshold shares
        let recovered = participant
            .recover_secret("test_key", shares[1..].to_vec())
            .unwrap();
        assert_eq!(recovered, secret);
    }
}
