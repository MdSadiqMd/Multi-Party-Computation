use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

const FIELD_SIZE: u8 = 255; // prime field size (GF(256))

#[derive(Debug, Error)]
pub enum ShamirError {
    #[error("Not enough shares to reconstruct secret")]
    NotEnoughShares,
    #[error("Invalid share format")]
    InvalidShareFormat,
    #[error("Random number generation failed")]
    RandomGenerationFailed,
    #[error("Duplicate share IDs")]
    DuplicateShareIds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShamirShare {
    pub id: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShamirSecret {
    pub threshold: u8,
    pub total_shares: u8,
    pub shares: Vec<ShamirShare>,
}

// Basic Galois Field (GF(256)) operations
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b // XOR for addition in GF(256)
}

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }

    // Use lookup tables for efficient multiplication in GF(256)
    // This is a simplified version - in production you'd use precomputed tables
    let mut result = 0;
    let mut a = a as u16;
    let mut b = b as u16;

    while b > 0 {
        if b & 1 == 1 {
            result ^= a as u8;
        }
        a = a << 1;
        if a & 0x100 != 0 {
            a ^= 0x11B; // x^8 + x^4 + x^3 + x + 1 (AES polynomial)
        }
        b >>= 1;
    }

    result as u8
}

fn gf_div(a: u8, b: u8) -> u8 {
    if b == 0 {
        panic!("Division by zero");
    }
    if a == 0 {
        return 0;
    }

    // Find b^-1 using extended Euclidean algorithm
    // For GF(256), b^254 = b^-1
    let mut result = 1;
    let mut exponent = 254;
    let mut base = b;

    while exponent > 0 {
        if exponent & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }

    gf_mul(a, result)
}

// Create polynomial for secret sharing
fn create_polynomial(secret_byte: u8, degree: u8) -> Vec<u8> {
    let mut poly = vec![secret_byte];
    let mut rng = OsRng;

    for _ in 0..degree {
        poly.push(rng.gen::<u8>());
    }

    poly
}

// Evaluate the polynomial at a given point
fn evaluate_polynomial(poly: &[u8], x: u8) -> u8 {
    let mut result = 0;
    let mut x_pow = 1;

    for coeff in poly {
        result = gf_add(result, gf_mul(*coeff, x_pow));
        x_pow = gf_mul(x_pow, x);
    }

    result
}

// Shamir Secret Sharing implementation
pub fn split_secret(
    secret: &[u8],
    threshold: u8,
    num_shares: u8,
) -> Result<ShamirSecret, ShamirError> {
    if threshold > num_shares {
        return Err(ShamirError::NotEnoughShares);
    }

    let mut shares: Vec<ShamirShare> = Vec::with_capacity(num_shares as usize);

    for &secret_byte in secret {
        // Create a polynomial where constant term is the secret byte
        let poly = create_polynomial(secret_byte, threshold - 1);

        for i in 1..=num_shares {
            if i as usize > shares.len() {
                shares.push(ShamirShare {
                    id: i,
                    value: Vec::new(),
                });
            }

            let evaluated = evaluate_polynomial(&poly, i);
            shares[(i - 1) as usize].value.push(evaluated);
        }
    }

    Ok(ShamirSecret {
        threshold,
        total_shares: num_shares,
        shares,
    })
}

// Lagrange basis polynomials for interpolation
fn lagrange_basis(x: u8, i: u8, x_values: &[u8]) -> u8 {
    let mut numerator = 1;
    let mut denominator = 1;

    for &j in x_values {
        if j == i {
            continue;
        }

        numerator = gf_mul(numerator, gf_add(x, j));
        denominator = gf_mul(denominator, gf_add(i, j));
    }

    gf_div(numerator, denominator)
}

// Reconstruct the secret from shares
pub fn reconstruct_secret(
    shares: &[ShamirShare],
    secret_len: usize,
) -> Result<Vec<u8>, ShamirError> {
    if shares.is_empty() {
        return Err(ShamirError::NotEnoughShares);
    }

    let mut seen_ids = std::collections::HashSet::new();
    for share in shares {
        if !seen_ids.insert(share.id) {
            return Err(ShamirError::DuplicateShareIds);
        }
    }

    let share_len = shares[0].value.len();
    if share_len == 0 {
        return Ok(Vec::new());
    }

    // If secret_len is specified, use it, otherwise use share_len
    let result_len = if secret_len > 0 {
        secret_len
    } else {
        share_len
    };

    // Get x-coordinates for interpolation
    let x_coords: Vec<u8> = shares.iter().map(|share| share.id).collect();

    // Reconstruct each byte of the secret
    let mut secret = Vec::with_capacity(result_len);

    for i in 0..share_len {
        let mut byte = 0;

        for j in 0..shares.len() {
            let share = &shares[j];
            if i >= share.value.len() {
                return Err(ShamirError::InvalidShareFormat);
            }

            let lagrange_coef = lagrange_basis(0, share.id, &x_coords);
            byte = gf_add(byte, gf_mul(share.value[i], lagrange_coef));
        }

        secret.push(byte);

        if secret.len() >= result_len {
            break;
        }
    }

    Ok(secret)
}

pub fn example_usage() {
    let secret = b"This is a secret message";
    let threshold = 3;
    let num_shares = 5;

    match split_secret(secret, threshold, num_shares) {
        Ok(shamir_secret) => {
            println!(
                "Secret split into {} shares, threshold: {}",
                num_shares, threshold
            );
            let subset_shares = shamir_secret.shares[0..threshold as usize].to_vec();
            match reconstruct_secret(&subset_shares, secret.len()) {
                Ok(reconstructed) => {
                    println!(
                        "Reconstructed secret: {}",
                        String::from_utf8_lossy(&reconstructed)
                    );
                }
                Err(e) => {
                    println!("Failed to reconstruct: {:?}", e);
                }
            }
        }
        Err(e) => {
            println!("Failed to split secret: {:?}", e);
        }
    }
}
