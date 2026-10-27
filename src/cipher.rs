//! The master secret cipher: a four-round Feistel network whose round function is
//! PBKDF2-HMAC-SHA256 keyed by the passphrase.

use sha2::Sha256;
use zeroize::Zeroizing;

use crate::Secret;

const BASE_ITERATIONS: u32 = 10_000;
const ROUNDS: u8 = 4;

/// Encrypt, or decrypt when `decrypt` is set. `data` must have an even length; callers check
/// this before calling.
pub(crate) fn feistel(
    data: &[u8],
    passphrase: &[u8],
    exponent: u8,
    identifier: u16,
    extendable: bool,
    decrypt: bool,
) -> Secret {
    debug_assert!(data.len().is_multiple_of(2));
    let salt: Vec<u8> = if extendable {
        Vec::new()
    } else {
        [b"shamir".as_slice(), &identifier.to_be_bytes()].concat()
    };
    let iterations = (BASE_ITERATIONS << exponent) / ROUNDS as u32;
    let (l, r) = data.split_at(data.len() / 2);
    let (mut l, mut r) = (Zeroizing::new(l.to_vec()), Zeroizing::new(r.to_vec()));
    let order: Vec<u8> = if decrypt {
        (0..ROUNDS).rev().collect()
    } else {
        (0..ROUNDS).collect()
    };
    for i in order {
        let password = Zeroizing::new([&[i][..], passphrase].concat());
        let salted = Zeroizing::new([&salt[..], &r[..]].concat());
        let mut f = Zeroizing::new(vec![0u8; r.len()]);
        pbkdf2::pbkdf2_hmac::<Sha256>(&password, &salted, iterations, &mut f);
        let next = Zeroizing::new(l.iter().zip(f.iter()).map(|(a, b)| a ^ b).collect());
        l = r;
        r = next;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(data.len()));
    out.extend_from_slice(&r);
    out.extend_from_slice(&l);
    out
}
