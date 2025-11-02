// Distributed Key Generation (DKG) Protocol
// Implements Pedersen DKG for threshold key generation
use crate::error::{MpcError, Result};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// DKG participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgParticipant {
    pub id: u32,
    pub public_key: CompressedRistretto,
    #[serde(skip)]
    _secret_key: Option<Scalar>,
}

// DKG share for a participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgShare {
    pub from: u32,
    pub to: u32,
    pub share: Scalar,
    pub commitment: Vec<CompressedRistretto>,
}

// DKG protocol state
#[derive(Debug)]
pub struct DkgProtocol {
    pub threshold: usize,
    pub total_participants: usize,
    pub participant_id: u32,
    secret_polynomial: Vec<Scalar>,
    pub commitments: HashMap<u32, Vec<CompressedRistretto>>,
    received_shares: HashMap<u32, Scalar>,
    pub public_key_shares: HashMap<u32, RistrettoPoint>,
}

impl DkgProtocol {
    // Initialize a new DKG protocol instance
    pub fn new(participant_id: u32, threshold: usize, total_participants: usize) -> Result<Self> {
        if threshold > total_participants {
            return Err(MpcError::InvalidMetadata);
        }
        if threshold < 1 {
            return Err(MpcError::InvalidMetadata);
        }

        Ok(DkgProtocol {
            threshold,
            total_participants,
            participant_id,
            secret_polynomial: Vec::new(),
            commitments: HashMap::new(),
            received_shares: HashMap::new(),
            public_key_shares: HashMap::new(),
        })
    }

    // Phase 1: Generate secret polynomial and commitments
    pub fn generate_shares(&mut self) -> Result<Vec<DkgShare>> {
        // Generate random polynomial of degree threshold-1
        self.secret_polynomial = (0..self.threshold)
            .map(|_| super::random_scalar())
            .collect();

        // Generate commitments to polynomial coefficients
        let commitments: Vec<CompressedRistretto> = self
            .secret_polynomial
            .iter()
            .map(|coeff| (RISTRETTO_BASEPOINT_POINT * coeff).compress())
            .collect();

        self.commitments
            .insert(self.participant_id, commitments.clone());

        // Generate shares for each participant
        let mut shares = Vec::new();
        for j in 1..=self.total_participants as u32 {
            if j == self.participant_id {
                continue;
            }

            let share_value = self.evaluate_polynomial(j);
            shares.push(DkgShare {
                from: self.participant_id,
                to: j,
                share: share_value,
                commitment: commitments.clone(),
            });
        }

        Ok(shares)
    }

    // Phase 2: Verify and aggregate received shares
    pub fn process_share(&mut self, share: DkgShare) -> Result<()> {
        // Verify the share using commitments
        if !self.verify_share(&share)? {
            return Err(MpcError::CryptoError(format!(
                "Invalid share from participant {}",
                share.from
            )));
        }

        // Store commitment
        self.commitments
            .insert(share.from, share.commitment.clone());

        // Aggregate share
        let existing = self
            .received_shares
            .entry(share.from)
            .or_insert(Scalar::zero());
        *existing += share.share;

        Ok(())
    }

    // Phase 3: Compute final key share and public key
    pub fn finalize(&mut self) -> Result<(Scalar, RistrettoPoint)> {
        if self.received_shares.len() < self.threshold - 1 {
            return Err(MpcError::CryptoError(format!(
                "Not enough shares: {} < {}",
                self.received_shares.len(),
                self.threshold - 1
            )));
        }

        // Compute own share from polynomial
        let own_share = self.evaluate_polynomial(self.participant_id);

        // Aggregate all shares (including own)
        let mut final_share = own_share;
        for (_, share) in &self.received_shares {
            final_share += share;
        }

        // Compute public key shares for all participants
        for (id, commitments) in &self.commitments {
            let mut public_share = RistrettoPoint::identity();
            let id_scalar = Scalar::from(*id);
            let mut id_power = Scalar::one();
            for commitment in commitments.iter() {
                public_share += commitment
                    .decompress()
                    .ok_or(MpcError::CryptoError("Invalid commitment".into()))?
                    * id_power;
                id_power *= id_scalar;
            }
            self.public_key_shares.insert(*id, public_share);
        }

        // Compute group public key
        let group_public_key = self
            .commitments
            .values()
            .map(|comms| {
                comms[0]
                    .decompress()
                    .ok_or(MpcError::CryptoError("Invalid commitment".into()))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .fold(RistrettoPoint::identity(), |acc, point| acc + point);

        Ok((final_share, group_public_key))
    }

    // Evaluate polynomial at a given x value
    fn evaluate_polynomial(&self, x: u32) -> Scalar {
        let x_scalar = Scalar::from(x);
        let mut result = Scalar::zero();
        let mut x_power = Scalar::one();

        for coeff in &self.secret_polynomial {
            result += coeff * x_power;
            x_power *= x_scalar;
        }

        result
    }

    // Verify a share using Feldman VSS
    fn verify_share(&self, share: &DkgShare) -> Result<bool> {
        let x = Scalar::from(self.participant_id);
        let mut expected = RistrettoPoint::identity();
        let mut x_power = Scalar::one();

        for commitment in &share.commitment {
            let point = commitment
                .decompress()
                .ok_or(MpcError::CryptoError("Invalid commitment".into()))?;
            expected += point * x_power;
            x_power *= x;
        }

        let actual = RISTRETTO_BASEPOINT_POINT * share.share;
        Ok(expected == actual)
    }
}

// DKG coordinator for managing the protocol
pub struct DkgCoordinator {
    pub threshold: usize,
    pub total_participants: usize,
    pub participants: HashMap<u32, DkgParticipant>,
    pub group_public_key: Option<RistrettoPoint>,
}

impl DkgCoordinator {
    pub fn new(threshold: usize, total_participants: usize) -> Result<Self> {
        if threshold > total_participants || threshold < 1 {
            return Err(MpcError::InvalidMetadata);
        }

        Ok(DkgCoordinator {
            threshold,
            total_participants,
            participants: HashMap::new(),
            group_public_key: None,
        })
    }

    // Register a participant
    pub fn register_participant(&mut self, participant: DkgParticipant) -> Result<()> {
        if self.participants.len() >= self.total_participants {
            return Err(MpcError::CryptoError("Too many participants".into()));
        }

        self.participants.insert(participant.id, participant);
        Ok(())
    }

    // Check if DKG is ready to start
    pub fn is_ready(&self) -> bool {
        self.participants.len() == self.total_participants
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dkg_protocol() {
        let threshold = 2;
        let total = 3;

        // Initialize protocols for each participant
        let mut protocols: Vec<DkgProtocol> = (1..=total)
            .map(|id| DkgProtocol::new(id as u32, threshold, total).unwrap())
            .collect();

        // Phase 1: Generate shares
        let mut all_shares = Vec::new();
        for protocol in &mut protocols {
            let shares = protocol.generate_shares().unwrap();
            all_shares.push(shares);
        }

        // Phase 2: Distribute and process shares
        for (_, shares) in all_shares.iter().enumerate() {
            for share in shares {
                let to_idx = (share.to - 1) as usize;
                protocols[to_idx].process_share(share.clone()).unwrap();
            }
        }

        // Phase 3: Finalize
        let mut group_keys = Vec::new();
        for protocol in &mut protocols {
            let (_share, group_key) = protocol.finalize().unwrap();
            group_keys.push(group_key);
        }

        // Verify all participants computed the same group public key
        for i in 1..group_keys.len() {
            assert_eq!(group_keys[0], group_keys[i]);
        }
    }
}
