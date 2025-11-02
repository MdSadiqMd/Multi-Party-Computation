pub mod dkg;
pub mod mpc;
pub mod shamir;
pub mod threshold_signatures;
pub mod zkp;

use crate::error::Result;
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng; // Use rand_core 0.5 directly for compatibility with curve25519-dalek
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

// Secure random number generator
pub fn secure_random() -> OsRng {
    OsRng
}

// Generate a secure random scalar
pub fn random_scalar() -> Scalar {
    Scalar::random(&mut secure_random())
}

// Compute SHA3-256 hash
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// Key derivation function using Argon2
pub fn derive_key(password: &[u8], salt: &[u8], output_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    use argon2::{
        password_hash::{PasswordHasher, SaltString},
        Argon2,
    };

    let argon2 = Argon2::default();
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| crate::error::MpcError::CryptoError(format!("Invalid salt: {}", e)))?;

    let password_hash = argon2.hash_password(password, &salt_string).map_err(|e| {
        crate::error::MpcError::CryptoError(format!("Key derivation failed: {}", e))
    })?;

    let hash = password_hash.hash.unwrap();
    let mut output = vec![0u8; output_len];
    output.copy_from_slice(&hash.as_bytes()[..output_len.min(hash.len())]);

    Ok(Zeroizing::new(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_random() {
        let scalar1 = random_scalar();
        let scalar2 = random_scalar();
        assert_ne!(scalar1, scalar2);
    }

    #[test]
    fn test_hash() {
        let data = b"test data";
        let hash1 = hash(data);
        let hash2 = hash(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }
}
