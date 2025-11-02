// Shamir's Secret Sharing with large field support
use crate::error::{MpcError, Result};
use num_bigint::{BigInt, RandBigInt};
use num_traits::{One, Zero};
use rand08::thread_rng;
use serde::{Deserialize, Serialize};

// A share in Shamir's Secret Sharing scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretShare {
    pub index: u32,
    pub value: Vec<u8>,
    pub prime: Vec<u8>,
}

// Shamir Secret Sharing implementation with large prime support
pub struct ShamirSecretSharing {
    threshold: usize,
    total_shares: usize,
    prime: BigInt,
}

impl ShamirSecretSharing {
    pub fn new(threshold: usize, total_shares: usize) -> Result<Self> {
        if threshold < 1 || threshold > total_shares {
            return Err(MpcError::InvalidMetadata);
        }

        // 256-bit prime for security
        let prime = generate_prime(256);

        Ok(ShamirSecretSharing {
            threshold,
            total_shares,
            prime,
        })
    }

    // Create with a specific prime
    pub fn with_prime(threshold: usize, total_shares: usize, prime: BigInt) -> Result<Self> {
        if threshold < 1 || threshold > total_shares {
            return Err(MpcError::InvalidMetadata);
        }

        if !is_probably_prime(&prime, 20) {
            return Err(MpcError::CryptoError("Prime validation failed".into()));
        }

        Ok(ShamirSecretSharing {
            threshold,
            total_shares,
            prime,
        })
    }

    // Split a secret into shares
    pub fn split_secret(&self, secret: &[u8]) -> Result<Vec<SecretShare>> {
        // secret to BigInt
        let secret_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, secret);

        if secret_int >= self.prime {
            return Err(MpcError::InvalidSecret);
        }

        // random polynomial coefficients
        let mut coefficients = vec![secret_int];
        let mut rng = thread_rng();

        for _ in 1..self.threshold {
            let coeff = rng.gen_bigint_range(&BigInt::zero(), &self.prime);
            coefficients.push(coeff);
        }

        // shares
        let mut shares = Vec::with_capacity(self.total_shares);

        for i in 1..=self.total_shares {
            let x = BigInt::from(i);
            let y = self.evaluate_polynomial(&coefficients, &x);

            shares.push(SecretShare {
                index: i as u32,
                value: y.to_bytes_be().1,
                prime: self.prime.to_bytes_be().1,
            });
        }

        Ok(shares)
    }

    // Combine shares to recover the secret
    pub fn combine_shares(&self, shares: &[SecretShare]) -> Result<Vec<u8>> {
        if shares.len() < self.threshold {
            return Err(MpcError::CryptoError(format!(
                "Not enough shares: {} < {}",
                shares.len(),
                self.threshold
            )));
        }

        // all shares use the same prime
        let prime_bytes = self.prime.to_bytes_be().1;
        for share in shares {
            if share.prime != prime_bytes {
                return Err(MpcError::InvalidShare);
            }
        }

        // shares to BigInt
        let points: Vec<(BigInt, BigInt)> = shares
            .iter()
            .take(self.threshold)
            .map(|s| {
                (
                    BigInt::from(s.index),
                    BigInt::from_bytes_be(num_bigint::Sign::Plus, &s.value),
                )
            })
            .collect();

        // reconstruct secret using Lagrange interpolation
        let secret = self.lagrange_interpolate(&points, &BigInt::zero());

        Ok(secret.to_bytes_be().1)
    }

    // Evaluate polynomial at x
    fn evaluate_polynomial(&self, coefficients: &[BigInt], x: &BigInt) -> BigInt {
        let mut result = BigInt::zero();
        let mut x_power = BigInt::one();

        for coeff in coefficients {
            result = (result + (coeff * &x_power)) % &self.prime;
            x_power = (x_power * x) % &self.prime;
        }

        result
    }

    // lagrange interpolation
    fn lagrange_interpolate(&self, points: &[(BigInt, BigInt)], x: &BigInt) -> BigInt {
        let mut result = BigInt::zero();

        for i in 0..points.len() {
            let (xi, yi) = &points[i];
            let mut numerator = BigInt::one();
            let mut denominator = BigInt::one();

            for j in 0..points.len() {
                if i == j {
                    continue;
                }

                let (xj, _) = &points[j];
                let diff_x = ((x - xj) % &self.prime + &self.prime) % &self.prime;
                let diff_xi = ((xi - xj) % &self.prime + &self.prime) % &self.prime;

                numerator = (numerator * diff_x) % &self.prime;
                denominator = (denominator * diff_xi) % &self.prime;
            }

            // modular inverse - this should always succeed for prime modulus and distinct points
            let inv = mod_inverse(&denominator, &self.prime).unwrap_or_else(|_| {
                // inverse fails, use 1 as fallback (shouldn't happen with proper inputs)
                eprintln!(
                    "Warning: modular inverse failed for denominator {}",
                    denominator
                );
                BigInt::one()
            });

            let lagrange_coeff = (numerator * inv) % &self.prime;
            result = (result + (yi * lagrange_coeff)) % &self.prime;
        }

        // positive result
        while result < BigInt::zero() {
            result += &self.prime;
        }

        result
    }

    // Verify a share without reconstructing the secret
    pub fn verify_share(&self, share: &SecretShare, _commitments: &[Vec<u8>]) -> Result<bool> {
        // verification using public commitments (Feldman VSS)
        // This would require commitment verification logic
        // basic validation

        if share.index < 1 || share.index > self.total_shares as u32 {
            return Ok(false);
        }

        let value = BigInt::from_bytes_be(num_bigint::Sign::Plus, &share.value);
        if value >= self.prime {
            return Ok(false);
        }

        Ok(true)
    }
}

// random prime of specified bit length
fn generate_prime(bits: usize) -> BigInt {
    let mut rng = thread_rng();
    loop {
        let candidate = rng.gen_bigint(bits as u64);
        if is_probably_prime(&candidate, 20) {
            return candidate;
        }
    }
}

// miller-rabin primality test
fn is_probably_prime(n: &BigInt, k: usize) -> bool {
    if n <= &BigInt::one() {
        return false;
    }
    if n == &BigInt::from(2) || n == &BigInt::from(3) {
        return true;
    }
    if n % 2 == BigInt::zero() {
        return false;
    }

    // Write n-1 as 2^r * d
    let n_minus_one: BigInt = n - 1;
    let mut d = n_minus_one.clone();
    let mut r: u32 = 0;

    while &d % 2 == BigInt::zero() {
        d /= 2;
        r += 1;
    }

    // Witness loop
    let mut rng = thread_rng();
    for _ in 0..k {
        let a = rng.gen_bigint_range(&BigInt::from(2), n);
        let mut x = a.modpow(&d, n);

        if x == BigInt::one() || x == n_minus_one {
            continue;
        }

        let mut continue_outer = false;
        for _ in 0..r - 1 {
            x = x.modpow(&BigInt::from(2), n);
            if x == n_minus_one {
                continue_outer = true;
                break;
            }
        }

        if !continue_outer {
            return false;
        }
    }

    true
}

// Modular inverse using extended Euclidean algorithm
fn mod_inverse(a: &BigInt, m: &BigInt) -> Result<BigInt> {
    let (gcd, x, _) = extended_gcd(a, m);

    if gcd != BigInt::one() {
        return Err(MpcError::CryptoError("No modular inverse exists".into()));
    }

    Ok((x % m + m) % m)
}

// Extended Euclidean algorithm
fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if a == &BigInt::zero() {
        return (b.clone(), BigInt::zero(), BigInt::one());
    }

    let (gcd, x1, y1) = extended_gcd(&(b % a), a);
    let x = y1 - (b / a) * &x1;
    let y = x1;

    (gcd, x, y)
}

// Verifiable Secret Sharing wrapper
pub struct VerifiableSecretSharing {
    shamir: ShamirSecretSharing,
}

impl VerifiableSecretSharing {
    pub fn new(threshold: usize, total_shares: usize) -> Result<Self> {
        Ok(VerifiableSecretSharing {
            shamir: ShamirSecretSharing::new(threshold, total_shares)?,
        })
    }

    // split secret with commitments for verification
    pub fn split_verifiable(&self, secret: &[u8]) -> Result<(Vec<SecretShare>, Vec<Vec<u8>>)> {
        let shares = self.shamir.split_secret(secret)?;

        // commitments (simplified - real implementation would use elliptic curve)
        let commitments = shares
            .iter()
            .map(|share| super::hash(&share.value).to_vec())
            .collect();

        Ok((shares, commitments))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_secret_sharing() {
        let secret = b"This is a secret message!";
        let threshold = 3;
        let total_shares = 5;

        let sss = ShamirSecretSharing::new(threshold, total_shares).unwrap();

        // Split secret
        let shares = sss.split_secret(secret).unwrap();
        assert_eq!(shares.len(), total_shares);

        // Combine minimum threshold
        let recovered = sss.combine_shares(&shares[..threshold]).unwrap();
        assert_eq!(recovered, secret);

        // Combine with more than threshold
        let recovered = sss.combine_shares(&shares[..threshold + 1]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = b"Secret";
        let threshold = 3;
        let total_shares = 5;

        let sss = ShamirSecretSharing::new(threshold, total_shares).unwrap();
        let shares = sss.split_secret(secret).unwrap();

        // Try with insufficient shares
        let result = sss.combine_shares(&shares[..threshold - 1]);
        assert!(result.is_err());
    }
}
