// ═══════════════════════════════════════════════════════════════════════
// Shamir's Secret Sharing — GF(256)
//
// Split a secret into N shares, any K of which can reconstruct it.
// Arithmetic in GF(256) using log/exp lookup tables for multiplication.
// Each byte of the secret is split independently using a random polynomial.
// ═══════════════════════════════════════════════════════════════════════

use crate::error::SecretError;

// ── GF(256) arithmetic ────────────────────────────────────────────────

// Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (AES)
// Reduction constant (low 8 bits): 0x1B

/// GF(256) addition is XOR.
pub fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// GF(256) multiplication using "Russian peasant" algorithm.
pub fn gf256_mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;
    while b > 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    result
}

/// GF(256) multiplicative inverse via Fermat's little theorem: a^254 = a^(-1).
pub fn gf256_inv(a: u8) -> Result<u8, SecretError> {
    if a == 0 {
        return Err(SecretError::InvalidShares("division by zero in GF(256)".into()));
    }
    let mut result = 1u8;
    let mut base = a;
    let mut exp = 254u8;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf256_mul(result, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    Ok(result)
}

/// GF(256) division: a / b = a * b^(-1).
pub fn gf256_div(a: u8, b: u8) -> Result<u8, SecretError> {
    if b == 0 {
        return Err(SecretError::InvalidShares("division by zero in GF(256)".into()));
    }
    if a == 0 {
        return Ok(0);
    }
    Ok(gf256_mul(a, gf256_inv(b)?))
}

/// Evaluate a polynomial with the given coefficients at point `x` in GF(256).
/// `coefficients[0]` is the constant term (a_0), `coefficients[1]` is the x term, etc.
pub fn evaluate_polynomial(coefficients: &[u8], x: u8) -> u8 {
    let mut value = 0u8;
    let mut x_pow = 1u8;
    for &coeff in coefficients {
        value = gf256_add(value, gf256_mul(coeff, x_pow));
        x_pow = gf256_mul(x_pow, x);
    }
    value
}

/// Compute the Lagrange basis polynomial for share `i` evaluated at x=0,
/// given a set of x-coordinates. Returns the Lagrange coefficient in GF(256).
pub fn lagrange_basis_at_zero(
    x_coords: &[u8],
    i: usize,
) -> Result<u8, SecretError> {
    let mut basis = 1u8;
    for (j, &x_j) in x_coords.iter().enumerate() {
        if i == j {
            continue;
        }
        let num = x_j;
        let den = gf256_add(x_j, x_coords[i]);
        basis = gf256_mul(basis, gf256_div(num, den)?);
    }
    Ok(basis)
}

/// Lagrange interpolation at x=0 given a set of (x, y) points in GF(256).
pub fn lagrange_interpolate(
    points: &[(u8, u8)],
) -> Result<u8, SecretError> {
    if points.is_empty() {
        return Err(SecretError::InvalidShares("no points provided".into()));
    }
    let x_coords: Vec<u8> = points.iter().map(|p| p.0).collect();
    let mut value = 0u8;
    for (i, &(_, y_i)) in points.iter().enumerate() {
        let basis = lagrange_basis_at_zero(&x_coords, i)?;
        value = gf256_add(value, gf256_mul(y_i, basis));
    }
    Ok(value)
}

// ── Share type ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub x: u8,
    pub data: Vec<u8>,
}

// ── Split and reconstruct ──────────────────────────────────────────────

/// Split a secret into `n` shares, requiring `k` to reconstruct.
/// Uses a deterministic seed for polynomial coefficients (for testability).
/// In production, use a CSPRNG.
pub fn split(
    secret: &[u8],
    n: u8,
    k: u8,
    entropy: &[u8],
) -> Result<Vec<Share>, SecretError> {
    if k < 2 {
        return Err(SecretError::InvalidShares("threshold must be >= 2".into()));
    }
    if n < k {
        return Err(SecretError::InvalidShares(
            format!("n ({n}) must be >= k ({k})")
        ));
    }
    if n < 2 {
        return Err(SecretError::InvalidShares("need at least 2 shares".into()));
    }
    if secret.is_empty() {
        return Err(SecretError::InvalidShares("empty secret".into()));
    }

    // Generate coefficients from entropy via simple hash-based expansion
    let coefficients = generate_coefficients(secret.len(), k as usize - 1, entropy);

    let mut shares: Vec<Share> = (0..n)
        .map(|i| Share { x: i + 1, data: Vec::with_capacity(secret.len()) })
        .collect();

    for (byte_idx, &secret_byte) in secret.iter().enumerate() {
        for share in shares.iter_mut() {
            let mut value = secret_byte; // a_0 = secret byte
            let mut x_pow = share.x;
            for coeff_idx in 0..(k as usize - 1) {
                let coeff = coefficients[byte_idx * (k as usize - 1) + coeff_idx];
                value = gf256_add(value, gf256_mul(coeff, x_pow));
                x_pow = gf256_mul(x_pow, share.x);
            }
            share.data.push(value);
        }
    }

    Ok(shares)
}

/// Reconstruct a secret from `k` or more shares using Lagrange interpolation.
pub fn reconstruct(shares: &[Share]) -> Result<Vec<u8>, SecretError> {
    if shares.is_empty() {
        return Err(SecretError::InvalidShares("no shares provided".into()));
    }
    if shares.len() < 2 {
        return Err(SecretError::InsufficientShares {
            required: 2,
            provided: shares.len() as u8,
        });
    }

    let data_len = shares[0].data.len();
    for s in shares {
        if s.data.len() != data_len {
            return Err(SecretError::InvalidShares("share lengths differ".into()));
        }
    }

    // Check for duplicate x values
    let mut seen = std::collections::HashSet::new();
    for s in shares {
        if !seen.insert(s.x) {
            return Err(SecretError::InvalidShares(
                format!("duplicate share x={}", s.x)
            ));
        }
    }

    let mut secret = vec![0u8; data_len];

    for byte_idx in 0..data_len {
        let mut value = 0u8;
        for (i, share_i) in shares.iter().enumerate() {
            let mut lagrange = 1u8;
            for (j, share_j) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                // lagrange *= x_j / (x_j - x_i)
                let num = share_j.x;
                let den = gf256_add(share_j.x, share_i.x); // subtraction = XOR in GF(256)
                lagrange = gf256_mul(lagrange, gf256_div(num, den)?);
            }
            value = gf256_add(value, gf256_mul(share_i.data[byte_idx], lagrange));
        }
        secret[byte_idx] = value;
    }

    Ok(secret)
}

/// Generate pseudo-random coefficients from entropy.
fn generate_coefficients(secret_len: usize, degree: usize, entropy: &[u8]) -> Vec<u8> {
    use rune_lang::stdlib::crypto::sign::hmac_sha3_256;

    let total = secret_len * degree;
    let mut coeffs = Vec::with_capacity(total);
    let mut counter = 0u64;

    while coeffs.len() < total {
        let mut input = Vec::new();
        input.extend_from_slice(entropy);
        input.extend_from_slice(&counter.to_le_bytes());
        let block = hmac_sha3_256(b"shamir-coefficients", &input);
        for &byte in &block {
            if coeffs.len() >= total {
                break;
            }
            // Ensure non-zero coefficients for highest degree
            if byte == 0 {
                coeffs.push(1);
            } else {
                coeffs.push(byte);
            }
        }
        counter += 1;
    }
    coeffs
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_add_is_xor() {
        assert_eq!(gf256_add(0, 0), 0);
        assert_eq!(gf256_add(0xFF, 0xFF), 0);
        assert_eq!(gf256_add(0xAA, 0x55), 0xFF);
    }

    #[test]
    fn test_gf256_mul_identity() {
        assert_eq!(gf256_mul(1, 42), 42);
        assert_eq!(gf256_mul(42, 1), 42);
    }

    #[test]
    fn test_gf256_mul_zero() {
        assert_eq!(gf256_mul(0, 42), 0);
        assert_eq!(gf256_mul(42, 0), 0);
    }

    #[test]
    fn test_gf256_div_identity() {
        assert_eq!(gf256_div(42, 1).unwrap(), 42);
    }

    #[test]
    fn test_gf256_div_self() {
        assert_eq!(gf256_div(42, 42).unwrap(), 1);
    }

    #[test]
    fn test_gf256_div_zero_divisor() {
        assert!(gf256_div(42, 0).is_err());
    }

    #[test]
    fn test_gf256_mul_div_roundtrip() {
        let a = 37u8;
        let b = 89u8;
        let c = gf256_mul(a, b);
        assert_eq!(gf256_div(c, b).unwrap(), a);
    }

    #[test]
    fn test_split_2_of_3() {
        let secret = b"hello";
        let shares = split(secret, 3, 2, b"entropy-seed").unwrap();
        assert_eq!(shares.len(), 3);
        for s in &shares {
            assert_eq!(s.data.len(), 5);
        }
    }

    #[test]
    fn test_reconstruct_2_of_3() {
        let secret = b"hello world";
        let shares = split(secret, 3, 2, b"entropy").unwrap();

        // Any 2 shares should reconstruct
        let r1 = reconstruct(&shares[0..2]).unwrap();
        assert_eq!(r1, secret);
        let r2 = reconstruct(&shares[1..3]).unwrap();
        assert_eq!(r2, secret);
        let r3 = reconstruct(&[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(r3, secret);
    }

    #[test]
    fn test_reconstruct_3_of_5() {
        let secret = b"secret data for sharing";
        let shares = split(secret, 5, 3, b"entropy-3of5").unwrap();
        assert_eq!(shares.len(), 5);

        let r = reconstruct(&shares[0..3]).unwrap();
        assert_eq!(r, secret);
        let r = reconstruct(&shares[2..5]).unwrap();
        assert_eq!(r, secret);
    }

    #[test]
    fn test_reconstruct_all_shares() {
        let secret = b"all";
        let shares = split(secret, 3, 2, b"e").unwrap();
        let r = reconstruct(&shares).unwrap();
        assert_eq!(r, secret);
    }

    #[test]
    fn test_split_threshold_too_low() {
        assert!(split(b"x", 3, 1, b"e").is_err());
    }

    #[test]
    fn test_split_n_less_than_k() {
        assert!(split(b"x", 2, 3, b"e").is_err());
    }

    #[test]
    fn test_split_empty_secret() {
        assert!(split(b"", 3, 2, b"e").is_err());
    }

    #[test]
    fn test_reconstruct_empty() {
        assert!(reconstruct(&[]).is_err());
    }

    #[test]
    fn test_reconstruct_single_share() {
        let shares = split(b"x", 3, 2, b"e").unwrap();
        assert!(reconstruct(&shares[0..1]).is_err());
    }

    #[test]
    fn test_reconstruct_duplicate_x() {
        let shares = split(b"x", 3, 2, b"e").unwrap();
        let duped = vec![shares[0].clone(), shares[0].clone()];
        assert!(reconstruct(&duped).is_err());
    }

    #[test]
    fn test_share_data_differs_per_share() {
        let shares = split(b"secret", 3, 2, b"entropy").unwrap();
        assert_ne!(shares[0].data, shares[1].data);
        assert_ne!(shares[1].data, shares[2].data);
    }

    #[test]
    fn test_single_byte_secret() {
        let secret = &[42u8];
        let shares = split(secret, 3, 2, b"e").unwrap();
        let r = reconstruct(&shares[0..2]).unwrap();
        assert_eq!(r, secret);
    }

    // ── evaluate_polynomial / lagrange_interpolate tests ────────────

    #[test]
    fn test_evaluate_polynomial_constant() {
        // p(x) = 42
        assert_eq!(evaluate_polynomial(&[42], 1), 42);
        assert_eq!(evaluate_polynomial(&[42], 5), 42);
    }

    #[test]
    fn test_evaluate_polynomial_linear() {
        // p(x) = 10 + 3*x  → p(0) = 10
        assert_eq!(evaluate_polynomial(&[10, 3], 0), 10);
    }

    #[test]
    fn test_lagrange_interpolate_recovers_secret() {
        let secret = b"test";
        let shares = split(secret, 3, 2, b"entropy").unwrap();
        // Lagrange interpolation at x=0 on each byte should recover secret
        for byte_idx in 0..secret.len() {
            let points: Vec<(u8, u8)> = shares[0..2]
                .iter()
                .map(|s| (s.x, s.data[byte_idx]))
                .collect();
            let recovered = lagrange_interpolate(&points).unwrap();
            assert_eq!(recovered, secret[byte_idx]);
        }
    }

    #[test]
    fn test_lagrange_interpolate_empty() {
        assert!(lagrange_interpolate(&[]).is_err());
    }

    #[test]
    fn test_lagrange_basis_at_zero() {
        // With 2 points, the basis for point 0 evaluated at x=0
        // should be x_1 / (x_1 - x_0) in GF(256)
        let basis = lagrange_basis_at_zero(&[1, 2], 0).unwrap();
        // x_1=2, x_0=1, den = 2 XOR 1 = 3, so basis = 2/3 in GF(256)
        assert_eq!(basis, gf256_div(2, 3).unwrap());
    }

    #[test]
    fn test_large_secret() {
        let secret: Vec<u8> = (0..=255).collect();
        let shares = split(&secret, 5, 3, b"large-entropy").unwrap();
        let r = reconstruct(&shares[0..3]).unwrap();
        assert_eq!(r, secret);
    }
}
