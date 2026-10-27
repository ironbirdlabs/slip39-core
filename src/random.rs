//! Where random bytes come from.

use zeroize::Zeroizing;

use crate::{Error, Secret};

/// A source of random bytes suitable for key material. Implement it to supply randomness from
/// a device or a host environment.
///
/// # Example
///
/// The counter below stands in for a real source so the example stays short; an
/// implementation for actual use must draw from a cryptographic generator.
///
/// ```
/// use slip39_core::{generate_mnemonics_with_rng, Error, GroupSpec, RandomSource};
///
/// struct Counter(u8);
///
/// impl RandomSource for Counter {
///     fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
///         for b in buf {
///             self.0 = self.0.wrapping_add(1);
///             *b = self.0;
///         }
///         Ok(())
///     }
/// }
///
/// let secret = [7u8; 16];
/// let groups = generate_mnemonics_with_rng(
///     1, &[GroupSpec::new(2, 3)], &secret, b"", true, 0, &mut Counter(0),
/// )?;
/// assert_eq!(groups[0].len(), 3);
/// # Ok::<(), Error>(())
/// ```
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
