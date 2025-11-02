use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
// Unit tests for cryptographic components
use multi_party_computation::crypto::*;

#[test]
fn test_secure_random_generation() {
    // Generate multiple random scalars
    let scalar1 = random_scalar();
    let scalar2 = random_scalar();
    let scalar3 = random_scalar();

    // Verify they're all different (extremely high probability)
    assert_ne!(scalar1, scalar2);
    assert_ne!(scalar2, scalar3);
    assert_ne!(scalar1, scalar3);
}

#[test]
fn test_hash_consistency() {
    let data1 = b"test data";
    let data2 = b"different data";

    // Same input should produce same hash
    let hash1a = hash(data1);
    let hash1b = hash(data1);
    assert_eq!(hash1a, hash1b);

    // Different input should produce different hash
    let hash2 = hash(data2);
    assert_ne!(hash1a, hash2);

    // Hash should be 32 bytes
    assert_eq!(hash1a.len(), 32);
}

#[test]
fn test_key_derivation() {
    let password = b"strong_password_123!@#";
    let salt = b"random_salt_value";

    // Derive key
    let key1 = derive_key(password, salt, 32).unwrap();
    assert_eq!(key1.len(), 32);

    // Same inputs should produce same key
    let key2 = derive_key(password, salt, 32).unwrap();
    assert_eq!(key1.as_ref(), key2.as_ref());

    // Different salt should produce different key
    let different_salt = b"different_salt";
    let key3 = derive_key(password, different_salt, 32).unwrap();
    assert_ne!(key1.as_ref(), key3.as_ref());
}

mod shamir_tests {
    use super::*;
    use multi_party_computation::crypto::shamir::*;

    #[test]
    fn test_secret_sharing_basic() {
        let secret = b"This is a secret!";
        let threshold = 2;
        let total_shares = 3;

        let sss = ShamirSecretSharing::new(threshold, total_shares).unwrap();

        // Split secret
        let shares = sss.split_secret(secret).unwrap();
        assert_eq!(shares.len(), total_shares);

        // Each share should have different value
        assert_ne!(shares[0].value, shares[1].value);
        assert_ne!(shares[1].value, shares[2].value);

        // Recover with minimum threshold
        let recovered = sss.combine_shares(&shares[..threshold]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_large_secret() {
        // Test with 256-bit secret
        let mut secret = vec![0u8; 32];
        for (i, byte) in secret.iter_mut().enumerate() {
            *byte = (i * 7 + 13) as u8;
        }

        let threshold = 5;
        let total_shares = 10;

        let sss = ShamirSecretSharing::new(threshold, total_shares).unwrap();

        let shares = sss.split_secret(&secret).unwrap();
        let recovered = sss.combine_shares(&shares[3..8]).unwrap();

        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_verifiable_secret_sharing() {
        let secret = b"Verifiable secret";
        let vss = VerifiableSecretSharing::new(3, 5).unwrap();

        let (shares, commitments) = vss.split_verifiable(secret).unwrap();

        assert_eq!(shares.len(), 5);
        assert_eq!(commitments.len(), 5);

        // Verify commitments are different
        assert_ne!(commitments[0], commitments[1]);
    }
}

mod dkg_tests {
    use super::*;
    use multi_party_computation::crypto::dkg::*;

    #[test]
    fn test_dkg_initialization() {
        let dkg = DkgProtocol::new(1, 3, 5).unwrap();
        assert_eq!(dkg.threshold, 3);
        assert_eq!(dkg.total_participants, 5);
        assert_eq!(dkg.participant_id, 1);
    }

    #[test]
    fn test_dkg_invalid_parameters() {
        // Threshold > total should fail
        let result = DkgProtocol::new(1, 6, 5);
        assert!(result.is_err());

        // Threshold = 0 should fail
        let result = DkgProtocol::new(1, 0, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_dkg_share_generation() {
        let mut dkg = DkgProtocol::new(1, 2, 3).unwrap();
        let shares = dkg.generate_shares().unwrap();

        // Should generate shares for all other participants
        assert_eq!(shares.len(), 2);

        // Shares should be for participants 2 and 3
        let recipients: Vec<u32> = shares.iter().map(|s| s.to).collect();
        assert!(recipients.contains(&2));
        assert!(recipients.contains(&3));
    }
}

mod threshold_signature_tests {
    use super::*;
    use multi_party_computation::crypto::threshold_signatures::*;
    use std::collections::HashMap;

    #[test]
    fn test_signature_share_generation() {
        let secret = random_scalar();
        let public_key = RISTRETTO_BASEPOINT_POINT * secret;

        let mut signer = ThresholdSignature::new(2, 1, secret, public_key, HashMap::new());

        let message = b"test message";
        let nonce = signer.generate_nonce_commitment(message).unwrap();

        // Nonce should be a valid point
        assert!(nonce.decompress().is_some());
    }

    #[test]
    fn test_lagrange_coefficients() {
        // Test Lagrange coefficient computation
        // This is internal to the module, but critical for correctness
        // Would need to expose for testing or test indirectly
    }
}

mod zkp_tests {
    use super::*;
    use multi_party_computation::crypto::zkp::*;

    #[test]
    fn test_schnorr_proof_correctness() {
        let secret = random_scalar();
        let public_key = RISTRETTO_BASEPOINT_POINT * secret;

        // Generate proof
        let proof = SchnorrProof::prove(&secret);

        // Verify with correct public key
        assert!(proof.verify(&public_key).unwrap());

        // Verify with incorrect public key fails
        let wrong_secret = random_scalar();
        let wrong_key = RISTRETTO_BASEPOINT_POINT * wrong_secret;
        assert!(!proof.verify(&wrong_key).unwrap());
    }

    #[test]
    fn test_schnorr_proof_soundness() {
        // Test that we can't forge a proof
        let secret1 = random_scalar();
        let secret2 = random_scalar();
        let public_key1 = RISTRETTO_BASEPOINT_POINT * secret1;
        let public_key2 = RISTRETTO_BASEPOINT_POINT * secret2;

        let proof1 = SchnorrProof::prove(&secret1);

        // Proof for one secret shouldn't verify for another
        assert!(!proof1.verify(&public_key2).unwrap());
    }

    #[test]
    fn test_range_proof_valid() {
        // Test valid range proofs
        let test_cases = vec![
            (0u64, 1),
            (1u64, 1),
            (255u64, 8),
            (256u64, 9),
            (65535u64, 16),
        ];

        for (value, bits) in test_cases {
            let proof = RangeProof::prove(value, bits).unwrap();
            assert!(proof.verify(bits).unwrap());
        }
    }

    #[test]
    fn test_range_proof_invalid() {
        // Test invalid range proofs
        let test_cases = vec![
            (2u64, 1),      // 2 doesn't fit in 1 bit
            (256u64, 8),    // 256 doesn't fit in 8 bits
            (65536u64, 16), // 65536 doesn't fit in 16 bits
        ];

        for (value, bits) in test_cases {
            let result = RangeProof::prove(value, bits);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_share_generation_proof() {
        use curve25519_dalek::scalar::Scalar;

        let coefficients = vec![random_scalar(), random_scalar(), random_scalar()];

        let shares: Vec<(u32, Scalar)> = (1..=5)
            .map(|i| {
                let mut share = Scalar::zero();
                let mut x_power = Scalar::one();
                let x = Scalar::from(i as u32);

                for coeff in &coefficients {
                    share += coeff * x_power;
                    x_power *= x;
                }

                (i as u32, share)
            })
            .collect();

        let proof = ShareGenerationProof::prove(&coefficients, &shares).unwrap();

        // Verify for each participant
        for (id, share) in &shares {
            assert!(proof.verify(*id, share).unwrap());
        }
    }
}

#[test]
fn test_mpc_participant_lifecycle() {
    use multi_party_computation::crypto::mpc::*;

    let mut participant = MpcParticipant::new(1, 2, 3).unwrap();
    assert_eq!(participant.id, 1);
    assert_eq!(participant.threshold, 2);
    assert_eq!(participant.total_participants, 3);

    // Test secret storage
    let secret = b"test secret";
    let shares = participant
        .store_secret("key1".to_string(), secret)
        .unwrap();
    assert_eq!(shares.len(), 3);

    // Test secret recovery
    let recovered = participant
        .recover_secret("key1", shares[1..].to_vec())
        .unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn test_secure_computation_basic() {
    use multi_party_computation::crypto::mpc::SecureComputation;

    let mut computation = SecureComputation::new(vec![1, 2, 3], 2).unwrap();

    // Add inputs
    computation.add_input(1, vec![5]).unwrap();
    computation.add_input(2, vec![10]).unwrap();
    computation.add_input(3, vec![15]).unwrap();

    // Compute sum
    let results = computation
        .compute(|inputs| {
            let sum = inputs.iter().map(|v| v[0]).sum();
            Ok(vec![sum])
        })
        .unwrap();

    assert_eq!(results.len(), 3);
    for (_, result) in results {
        assert_eq!(result, vec![30]);
    }
}
