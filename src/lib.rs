//! A minimal implementation of SLIP-39, Shamir's Secret Sharing for mnemonic codes.
//!
//! Written from the specification and tested against the reference implementation
//! (trezor/python-shamir-mnemonic 0.3.1) and its published test vectors. Includes the
//! two-level group scheme, passphrase encryption and the extendable backup flag.
//!
//! The API has three layers. [`generate_mnemonics`] and [`combine_mnemonics`] do everything
//! in one call. [`EncryptedSecret`] exposes the passphrase step and the sharing step
//! separately, as the specification defines them. [`Share`] encodes and decodes single
//! mnemonics. Randomness comes from a [`RandomSource`] supplied by the caller, or from the
//! operating system through [`OsRandom`] when the `getrandom` feature is on, as it is by default.
//!
//! Buffers holding secrets are wrapped in [`Zeroizing`], which attempts to overwrite them when
//! dropped. This is best effort: it does not cover copies made by the compiler, allocator or
//! operating system, nor the mnemonic strings returned to the caller.
//!
//! # Example
//!
//! ```
//! use slip39_core::{combine_mnemonics, generate_mnemonics, GroupSpec};
//!
//! let secret = [0x42u8; 32];
//!
//! // One group of five shares, any three of which recover the secret.
//! let groups = generate_mnemonics(1, &[GroupSpec::new(3, 5)], &secret, b"", true, 1)?;
//! let shares: Vec<&str> = groups[0].iter().map(String::as_str).collect();
//!
//! // Later, with three of them, in any order.
//! let recovered = combine_mnemonics(&shares[1..4], b"")?;
//! assert_eq!(*recovered, secret);
//! # Ok::<(), slip39_core::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod cipher;
mod error;
mod gf256;
mod random;
mod rs1024;
mod secret;
mod shamir;
mod share;

pub use error::Error;
#[cfg(feature = "getrandom")]
pub use random::OsRandom;
pub use random::RandomSource;
pub use secret::{EncryptedSecret, GroupSpec};
pub use share::{wordlist, Share, ShareHeader};
pub use zeroize::Zeroizing;

/// A byte buffer that the wrapper attempts to overwrite when dropped.
///
/// Buffers of this type are meant to be allocated at their final size: a `Vec` that grows
/// moves to a new allocation and leaves the old one behind without overwriting it, which
/// `Zeroizing` does not cover.
pub(crate) type Secret = Zeroizing<Vec<u8>>;

/// Split `master_secret` into groups of mnemonics using randomness from the operating system.
/// See [`generate_mnemonics_with_rng`] for the parameters.
#[cfg(feature = "getrandom")]
pub fn generate_mnemonics(
    group_threshold: u8,
    groups: &[GroupSpec],
    master_secret: &[u8],
    passphrase: &[u8],
    extendable: bool,
    iteration_exponent: u8,
) -> Result<Vec<Vec<String>>, Error> {
    generate_mnemonics_with_rng(
        group_threshold,
        groups,
        master_secret,
        passphrase,
        extendable,
        iteration_exponent,
        &mut OsRandom,
    )
}

/// Split `master_secret` into groups of mnemonics.
///
/// `group_threshold` of the `groups` are needed to recover. `master_secret` must be at least
/// 16 bytes with an even length; 16 and 32 bytes are the sizes the specification requires
/// implementations to support, and other sizes may not be accepted by other software or
/// devices. `iteration_exponent` scales the PBKDF2 cost as `10000 << e`. The specification
/// recommends `extendable` for newly created shares.
pub fn generate_mnemonics_with_rng<R: RandomSource + ?Sized>(
    group_threshold: u8,
    groups: &[GroupSpec],
    master_secret: &[u8],
    passphrase: &[u8],
    extendable: bool,
    iteration_exponent: u8,
    rng: &mut R,
) -> Result<Vec<Vec<String>>, Error> {
    // Check the cheap parameters before paying for the key derivation.
    secret::validate_groups(group_threshold, groups)?;
    let encrypted = EncryptedSecret::encrypt(
        master_secret,
        passphrase,
        extendable,
        iteration_exponent,
        rng,
    )?;
    let groups = encrypted.split(group_threshold, groups, rng)?;
    Ok(groups
        .iter()
        .map(|g| g.iter().map(Share::to_mnemonic).collect())
        .collect())
}

/// Recover the master secret from exactly a threshold number of groups, each holding exactly
/// its member threshold of mnemonics. Order does not matter, identical duplicates are ignored,
/// and word case is ignored. The result is returned in a [`Zeroizing`] wrapper.
pub fn combine_mnemonics<S: AsRef<str>>(
    mnemonics: &[S],
    passphrase: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let shares = mnemonics
        .iter()
        .map(|m| Share::from_mnemonic(m.as_ref()))
        .collect::<Result<Vec<Share>, Error>>()?;
    Ok(EncryptedSecret::recover(&shares)?.decrypt(passphrase))
}

/// Hooks for the fuzz harnesses, compiled only under `cargo fuzz`, which sets `--cfg fuzzing`.
#[cfg(fuzzing)]
pub mod fuzz_hooks {
    /// The RS1024 checksum words for `data`, so a harness can get past the checksum gate.
    pub fn checksum(data: &[u16], extendable: bool) -> [u16; 3] {
        crate::rs1024::checksum(data, crate::share::customization(extendable))
    }
}

/// Includes README.md as documentation so its code example is compiled and run by `cargo test`.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
mod readme {}
