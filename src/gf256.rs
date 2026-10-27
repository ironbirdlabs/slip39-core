//! Arithmetic in GF(256) with the AES polynomial x^8 + x^4 + x^3 + x + 1, and Lagrange
//! interpolation over it.

use zeroize::Zeroizing;

use crate::{Error, Secret};

/// Multiply written without lookup tables or data-dependent branches, to avoid secret-dependent
/// memory access. No constant-time behaviour is promised; compilers may transform this code.
pub(crate) fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    for _ in 0..8 {
        r ^= a & 0u8.wrapping_sub(b & 1);
        let carry = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1b & carry);
        b >>= 1;
    }
    r
}

/// Inverse by exponentiation: a^254 == a^-1. In this crate it is applied to x-coordinates,
/// which are not secret.
pub(crate) fn inv(a: u8) -> u8 {
    let (mut result, mut base) = (1u8, a);
    for bit in 0..8 {
        if (254u8 >> bit) & 1 == 1 {
            result = mul(result, base);
        }
        base = mul(base, base);
    }
    result
}

/// Lagrange interpolation at `x` of the byte-wise polynomials through `points`.
pub(crate) fn interpolate(points: &[(u8, &[u8])], x: u8) -> Result<Secret, Error> {
    let len = points.first().ok_or(Error::Empty)?.1.len();
    for (i, &(xi, yi)) in points.iter().enumerate() {
        if points[..i].iter().any(|&(xj, _)| xj == xi) {
            return Err(Error::DuplicateIndex);
        }
        if yi.len() != len {
            return Err(Error::ValueLengthMismatch);
        }
    }
    if let Some(&(_, y)) = points.iter().find(|&&(xi, _)| xi == x) {
        return Ok(Zeroizing::new(y.to_vec()));
    }
    let mut result = Zeroizing::new(vec![0u8; len]);
    for (i, &(xi, yi)) in points.iter().enumerate() {
        let (mut num, mut den) = (1u8, 1u8);
        for (j, &(xj, _)) in points.iter().enumerate() {
            if i != j {
                num = mul(num, x ^ xj);
                den = mul(den, xi ^ xj);
            }
        }
        let basis = mul(num, inv(den));
        for (r, &y) in result.iter_mut().zip(yi) {
            *r ^= mul(y, basis);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_round_trips() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1, "a = {a}");
        }
    }

    #[test]
    fn interpolation_recovers_a_known_polynomial() {
        // f(x) = 3x + 5 over GF(256) for each byte position; points at x = 1 and x = 2.
        let f = |x: u8| mul(3, x) ^ 5;
        let (y1, y2) = ([f(1), f(1)], [f(2), f(2)]);
        let points = [(1u8, &y1[..]), (2u8, &y2[..])];
        assert_eq!(*interpolate(&points, 0).unwrap(), vec![5, 5]);
        assert_eq!(*interpolate(&points, 7).unwrap(), vec![f(7), f(7)]);
        assert_eq!(
            interpolate(&[(1, &y1[..]), (1, &y2[..])], 0),
            Err(Error::DuplicateIndex)
        );
        assert_eq!(
            interpolate(&[(1, &y1[..]), (2, &y2[..1])], 0),
            Err(Error::ValueLengthMismatch)
        );
        assert_eq!(interpolate(&[], 0), Err(Error::Empty));
    }
}
