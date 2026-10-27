//! Where random bytes come from.

use zeroize::Zeroizing;

use crate::{Error, Secret};

/// A source of random bytes suitable for key material. Implement it to supply randomness from
/// a device or a host environment.
pub trait RandomSource {
    /// Fill `buf` entirely with random bytes.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error>;
}

impl<T: RandomSource + ?Sized> RandomSource for &mut T {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        (**self).fill(buf)
    }
}

/// Randomness from the operating system, through the `getrandom` crate.
#[cfg(feature = "getrandom")]
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandom;

#[cfg(feature = "getrandom")]
impl RandomSource for OsRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(buf).map_err(|_| Error::Random)
    }
}

pub(crate) fn random_bytes<R: RandomSource + ?Sized>(
    rng: &mut R,
    n: usize,
) -> Result<Secret, Error> {
    let mut buf = Zeroizing::new(vec![0u8; n]);
    rng.fill(&mut buf)?;
    Ok(buf)
}
