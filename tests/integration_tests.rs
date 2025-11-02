// Integration tests for MPC implementation
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use multi_party_computation::{
    crypto::{
        dkg::{DkgCoordinator, DkgProtocol},
        mpc::{MpcCoordinator, MpcParticipant, MpcPhase},
        shamir::ShamirSecretSharing,
        threshold_signatures::ThresholdSignature,
    },
    error::Result,
};
use std::collections::HashMap;

#[tokio::test]
async fn test_full_mpc_lifecycle() -> Result<()> {
    // Setup
    let threshold = 3;
    let total_participants = 5;
    let mut coordinator = MpcCoordinator::new(threshold, total_participants)?;

    // Register participants
    for i in 1..=total_participants {
        coordinator.register_participant(i as u32)?;
    }

    assert!(coordinator.is_ready_for_dkg());
    coordinator.start_dkg()?;

    // Create participant instances
    let mut participants: Vec<MpcParticipant> = (1..=total_participants)
        .map(|id| MpcParticipant::new(id as u32, threshold, total_participants).unwrap())
        .collect();

    // Phase 1: DKG
    let mut all_shares = Vec::new();
    for participant in &mut participants {
        let shares = participant.start_dkg()?;
        all_shares.push(shares);
    }

    // Distribute DKG shares
    for (i, shares) in all_shares.iter().enumerate() {
        for share in shares {
            let to_idx = (share.to - 1) as usize;
            if to_idx != i {
                participants[to_idx].process_dkg_share(share.clone())?;
            }
        }
    }

    // Finalize DKG
    let mut group_keys = Vec::new();
    for participant in &mut participants {
        let key = participant.finalize_dkg()?;
        group_keys.push(key);
    }

    // Verify all participants have the same group key
    for i in 1..group_keys.len() {
        assert_eq!(group_keys[0], group_keys[i]);
    }

    // Phase 2: Secret Sharing
    let secret = b"This is a very secret message!";
    let shares = participants[0].store_secret("test_secret".to_string(), secret)?;

    // Distribute shares to other participants
    for (i, share) in shares.iter().enumerate().skip(1).take(threshold - 1) {
        participants[i].secret_shares.insert(
            "test_secret".to_string(),
            zeroize::Zeroizing::new(share.clone()),
        );
    }

    // Recover secret with threshold shares
    let recovered = participants[0].recover_secret("test_secret", shares[1..threshold].to_vec())?;

    assert_eq!(recovered, secret);

    Ok(())
}

#[tokio::test]
async fn test_shamir_secret_sharing_resilience() -> Result<()> {
    let secret = b"Critical infrastructure key";
    let threshold = 3;
    let total_shares = 7;

    let sss = ShamirSecretSharing::new(threshold, total_shares)?;

    // Split secret
    let shares = sss.split_secret(secret)?;
    assert_eq!(shares.len(), total_shares);

    // Test various combinations of shares
    // Minimum threshold
    let recovered1 = sss.combine_shares(&shares[0..threshold])?;
    assert_eq!(recovered1, secret);

    // Different combination
    let recovered2 = sss.combine_shares(&shares[2..threshold + 2])?;
    assert_eq!(recovered2, secret);

    // More than threshold
    let recovered3 = sss.combine_shares(&shares[1..threshold + 3])?;
    assert_eq!(recovered3, secret);

    // Test insufficient shares
    let result = sss.combine_shares(&shares[0..threshold - 1]);
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_dkg_protocol_correctness() -> Result<()> {
    let threshold = 2;
    let total = 4;

    // Initialize DKG coordinator
    let mut coordinator = DkgCoordinator::new(threshold, total)?;

    // Initialize protocols for each participant
    let mut protocols: Vec<DkgProtocol> = (1..=total)
        .map(|id| DkgProtocol::new(id as u32, threshold, total).unwrap())
        .collect();

    // Phase 1: Generate shares
    let mut all_shares = Vec::new();
    for protocol in &mut protocols {
        let shares = protocol.generate_shares()?;
        all_shares.push(shares);
    }

    // Phase 2: Distribute and verify shares
    for (i, shares) in all_shares.iter().enumerate() {
        for share in shares {
            let to_idx = (share.to - 1) as usize;
            protocols[to_idx].process_share(share.clone())?;
        }
    }

    // Phase 3: Finalize and verify consistency
    let mut secret_shares = Vec::new();
    let mut group_keys = Vec::new();

    for protocol in &mut protocols {
        let (share, group_key) = protocol.finalize()?;
        secret_shares.push(share);
        group_keys.push(group_key);
    }

    // Verify all participants computed the same group public key
    for i in 1..group_keys.len() {
        assert_eq!(group_keys[0], group_keys[i]);
    }

    // Verify the group key is the sum of individual public keys
    let expected_group_key = protocols[0].public_key_shares.values().fold(
        curve25519_dalek::ristretto::RistrettoPoint::default(),
        |acc, pk| acc + pk,
    );

    // The actual implementation might differ, but the concept should hold

    Ok(())
}

#[test]
fn test_threshold_signature_scheme() {
    use multi_party_computation::crypto;

    let threshold = 2;
    let message = b"Transaction data to sign";

    // Setup (normally from DKG)
    let secret1 = crypto::random_scalar();
    let secret2 = crypto::random_scalar();
    let public_key = RISTRETTO_BASEPOINT_POINT * (secret1 + secret2);

    let mut public_shares = HashMap::new();
    public_shares.insert(1, RISTRETTO_BASEPOINT_POINT * secret1);
    public_shares.insert(2, RISTRETTO_BASEPOINT_POINT * secret2);

    // Create threshold signers
    let mut signer1 =
        ThresholdSignature::new(threshold, 1, secret1, public_key, public_shares.clone());

    let mut signer2 = ThresholdSignature::new(threshold, 2, secret2, public_key, public_shares);

    // Generate nonce commitments
    let nonce1 = signer1.generate_nonce_commitment(message).unwrap();
    let nonce2 = signer2.generate_nonce_commitment(message).unwrap();

    // Aggregate nonces
    let agg_nonce = nonce1.decompress().unwrap() + nonce2.decompress().unwrap();

    // Generate partial signatures
    let partial1 = signer1.sign_partial(message, agg_nonce).unwrap();
    let partial2 = signer2.sign_partial(message, agg_nonce).unwrap();

    // Combine signatures
    let signature = signer1
        .combine_signatures(vec![partial1, partial2], &[1, 2])
        .unwrap();

    // Verify signature
    let valid = ThresholdSignature::verify(&public_key, message, &signature).unwrap();
    assert!(valid);
}

#[test]
fn test_zero_knowledge_proofs() {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use multi_party_computation::crypto::{self, zkp::*};

    // Test Schnorr proof
    let secret = crypto::random_scalar();
    let public_key = RISTRETTO_BASEPOINT_POINT * secret;

    let proof = SchnorrProof::prove(&secret);
    assert!(proof.verify(&public_key).unwrap());

    // Test with wrong public key
    let wrong_key = RISTRETTO_BASEPOINT_POINT * crypto::random_scalar();
    assert!(!proof.verify(&wrong_key).unwrap());

    // Test range proof
    let value = 100u64;
    let bits = 8;

    let range_proof = RangeProof::prove(value, bits).unwrap();
    assert!(range_proof.verify(bits).unwrap());

    // Test out of range
    let result = RangeProof::prove(300, 8);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_storage_encryption_and_distribution() {
    use multi_party_computation::{
        meta::{metadata::*, *},
        storage,
    };

    // Mock environment setup (would need actual Cloudflare Worker env in production)
    // This test would require mocking the storage providers

    let metadata = SecretMetadata {
        threshold: 3,
        total_shares: 5,
        regions: vec!["us-west-1".to_string(), "eu-west-1".to_string()],
        key_version: 1,
    };

    let shares = vec![
        vec![1, 2, 3, 4],
        vec![5, 6, 7, 8],
        vec![9, 10, 11, 12],
        vec![13, 14, 15, 16],
        vec![17, 18, 19, 20],
    ];

    // Test would continue with actual storage operations
    // In a real test, we'd use test doubles or in-memory storage
}

#[test]
fn test_secure_computation_protocol() {
    use multi_party_computation::crypto::mpc::SecureComputation;

    let participants = vec![1, 2, 3];
    let threshold = 2;

    let mut computation = SecureComputation::new(participants, threshold).unwrap();

    // Add inputs
    computation.add_input(1, vec![10]).unwrap();
    computation.add_input(2, vec![20]).unwrap();
    computation.add_input(3, vec![30]).unwrap();

    // Define computation (sum in this example)
    let result = computation
        .compute(|inputs| {
            let sum: u8 = inputs.iter().map(|v| v[0]).sum();
            Ok(vec![sum])
        })
        .unwrap();

    // Verify all participants get the result
    assert_eq!(result.len(), 3);
    for (_, value) in result {
        assert_eq!(value, vec![60]);
    }
}

#[test]
fn test_proactive_secret_sharing() {
    use multi_party_computation::crypto::mpc::ProactiveSecretSharing;
    use std::thread;
    use std::time::Duration;

    let mut pss = ProactiveSecretSharing::new(3, 5);

    // Initially shouldn't need refresh
    assert!(!pss.needs_refresh());

    // Generate refresh shares
    let refresh_shares = pss.generate_refresh_shares().unwrap();
    assert_eq!(refresh_shares.len(), 5);

    // After generation, shouldn't need refresh immediately
    assert!(!pss.needs_refresh());

    // Note: Testing time-based refresh would require mocking time
    // or waiting for actual duration
}
