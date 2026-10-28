//! Shamir's secret sharing as SLIP-39 specifies it: byte-wise over GF(256), with the secret at
//! x = 255 and a digest share at x = 254 intended to let recovery detect wrong or corrupted
//! shares.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::gf256::interpolate;
use crate::random::{random_bytes, RandomSource};
use crate::{Error, Secret};

/// The most shares a group may hold, and the most groups a set may hold.
pub(crate) const MAX_SHARE_COUNT: u8 = 16;
const DIGEST_LEN: usize = 4;
const SECRET_INDEX: u8 = 255;
const DIGEST_INDEX: u8 = 254;

fn digest(random: &[u8], secret: &[u8]) -> [u8; DIGEST_LEN] {
    let mut mac = Hmac::<Sha256>::new_from_slice(random).expect("HMAC accepts any key length");
    mac.update(secret);
    let out = mac.finalize().into_bytes();
    out[..DIGEST_LEN].try_into().expect("digest is 32 bytes")
}

/// Split `secret` into `count` shares of which any `threshold` recover it. Callers validate
/// the parameters before reaching here.
pub(crate) fn split_secret<R: RandomSource + ?Sized>(
    rng: &mut R,
    threshold: u8,
    count: u8,
    secret: &[u8],
) -> Result<Vec<(u8, Secret)>, Error> {
    debug_assert!((1..=count).contains(&threshold) && count <= MAX_SHARE_COUNT);
    if threshold == 1 {
        return Ok((0..count)
            .map(|i| (i, Zeroizing::new(secret.to_vec())))
            .collect());
    }
    let mut shares = Vec::with_capacity(count as usize);
    for i in 0..threshold - 2 {
        shares.push((i, random_bytes(rng, secret.len())?));
    }
    let random_part = random_bytes(rng, secret.len() - DIGEST_LEN)?;
    let mut digest_share = Zeroizing::new(Vec::with_capacity(secret.len()));
    digest_share.extend_from_slice(&digest(&random_part, secret));
    digest_share.extend_from_slice(&random_part);
    let mut base: Vec<(u8, &[u8])> = shares.iter().map(|(x, y)| (*x, y.as_slice())).collect();
    base.push((DIGEST_INDEX, &digest_share));
    base.push((SECRET_INDEX, secret));
    let mut rest = Vec::new();
    for i in threshold - 2..count {
        rest.push((i, interpolate(&base, i)?));
    }
    shares.extend(rest);
    Ok(shares)
}

/// Recover the secret from exactly `threshold` shares, checking the digest.
pub(crate) fn recover_secret(threshold: u8, shares: &[(u8, &[u8])]) -> Result<Secret, Error> {
    if threshold == 1 {
        let first = shares.first().ok_or(Error::Empty)?;
        return Ok(Zeroizing::new(first.1.to_vec()));
    }
    let secret = interpolate(shares, SECRET_INDEX)?;
    let digest_share = interpolate(shares, DIGEST_INDEX)?;
    let (d, random_part) = digest_share.split_at(DIGEST_LEN);
    if !bool::from(d.ct_eq(&digest(random_part, &secret)[..])) {
        return Err(Error::Digest);
    }
    Ok(secret)
}
