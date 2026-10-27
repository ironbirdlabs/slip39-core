//! The encrypted master secret: the passphrase layer and the sharing layer, kept together so
//! that shares made from it carry the parameters it was encrypted with.

use std::collections::BTreeMap;
use std::fmt;

use zeroize::Zeroizing;

use crate::cipher::feistel;
use crate::random::{random_bytes, RandomSource};
use crate::shamir::{recover_secret, split_secret, MAX_SHARE_COUNT};
use crate::share::{Share, ShareHeader, EXP_BITS, ID_BITS, MIN_SECRET_BYTES};
use crate::{Error, Secret};

/// One group of shares: `threshold` of its `count` members recover the group's part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupSpec {
    /// Members needed to recover the group's part, 1 to `count`.
    pub threshold: u8,
    /// Members issued, 1 to 16.
    pub count: u8,
}

impl GroupSpec {
    /// A group of `count` members of which `threshold` are needed.
    pub const fn new(threshold: u8, count: u8) -> Self {
        Self { threshold, count }
    }
}

pub(crate) fn validate_groups(group_threshold: u8, groups: &[GroupSpec]) -> Result<(), Error> {
    if groups.is_empty() || groups.len() > MAX_SHARE_COUNT as usize {
        return Err(Error::InvalidGroups);
    }
    if group_threshold < 1 || group_threshold as usize > groups.len() {
        return Err(Error::InvalidGroups);
    }
    for (i, g) in groups.iter().enumerate() {
        let ok = (1..=MAX_SHARE_COUNT).contains(&g.count)
            && (1..=g.count).contains(&g.threshold)
            && !(g.threshold == 1 && g.count > 1);
        if !ok {
            return Err(Error::InvalidGroup { group: i as u8 });
        }
    }
    Ok(())
}

/// A master secret encrypted under a passphrase, kept together with the identifier, flag and
/// exponent that its shares must carry. Shares made through [`EncryptedSecret::split`] take
/// those parameters from this value rather than from the caller.
///
/// # Example
///
/// ```
/// use slip39_core::{EncryptedSecret, GroupSpec, OsRandom};
///
/// let secret = [7u8; 16];
/// let encrypted = EncryptedSecret::encrypt(&secret, b"", true, 1, &mut OsRandom)?;
/// let groups = encrypted.split(1, &[GroupSpec::new(2, 3)], &mut OsRandom)?;
///
/// // Any two of the three shares rebuild the same encrypted value.
/// let recovered = EncryptedSecret::recover(&groups[0][1..])?;
/// assert_eq!(recovered, encrypted);
/// assert_eq!(*recovered.decrypt(b""), secret);
/// # Ok::<(), slip39_core::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedSecret {
    identifier: u16,
    extendable: bool,
    iteration_exponent: u8,
    ciphertext: Secret,
}

impl fmt::Debug for EncryptedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedSecret")
            .field("identifier", &self.identifier)
            .field("extendable", &self.extendable)
            .field("iteration_exponent", &self.iteration_exponent)
            .field("ciphertext", &"<redacted>")
            .finish()
    }
}

impl EncryptedSecret {
    /// Encrypt `secret` under `passphrase` with a fresh random identifier.
    ///
    /// `secret` must be at least 16 bytes with an even length; 16 and 32 bytes are the sizes
    /// the specification requires implementations to support. `iteration_exponent` scales the
    /// PBKDF2 cost as `10000 << e`. The specification recommends `extendable` for new shares.
    pub fn encrypt<R: RandomSource + ?Sized>(
        secret: &[u8],
        passphrase: &[u8],
        extendable: bool,
        iteration_exponent: u8,
        rng: &mut R,
    ) -> Result<Self, Error> {
        if secret.len() < MIN_SECRET_BYTES || !secret.len().is_multiple_of(2) {
            return Err(Error::InvalidSecretLength);
        }
        if !passphrase.iter().all(|c| (32..=126).contains(c)) {
            return Err(Error::InvalidPassphrase);
        }
        if iteration_exponent >= 1 << EXP_BITS {
            return Err(Error::InvalidExponent);
        }
        let id = random_bytes(rng, 2)?;
        let identifier = u16::from_be_bytes([id[0], id[1]]) & ((1 << ID_BITS) - 1);
        let ciphertext = feistel(
            secret,
            passphrase,
            iteration_exponent,
            identifier,
            extendable,
            false,
        );
        Ok(Self {
            identifier,
            extendable,
            iteration_exponent,
            ciphertext,
        })
    }

    /// The random identifier shared by every share of this secret.
    pub fn identifier(&self) -> u16 {
        self.identifier
    }

    /// Whether the extendable backup format is in use.
    pub fn extendable(&self) -> bool {
        self.extendable
    }

    /// The PBKDF2 cost exponent.
    pub fn iteration_exponent(&self) -> u8 {
        self.iteration_exponent
    }

    /// Decrypt with `passphrase`. As the specification defines it, a wrong passphrase yields a
    /// different secret rather than an error.
    pub fn decrypt(&self, passphrase: &[u8]) -> Zeroizing<Vec<u8>> {
        feistel(
            &self.ciphertext,
            passphrase,
            self.iteration_exponent,
            self.identifier,
            self.extendable,
            true,
        )
    }

    /// Split into groups of shares, of which `group_threshold` groups are needed to recover.
    pub fn split<R: RandomSource + ?Sized>(
        &self,
        group_threshold: u8,
        groups: &[GroupSpec],
        rng: &mut R,
    ) -> Result<Vec<Vec<Share>>, Error> {
        validate_groups(group_threshold, groups)?;
        let group_secrets =
            split_secret(rng, group_threshold, groups.len() as u8, &self.ciphertext)?;
        let mut out = Vec::with_capacity(groups.len());
        for (spec, (group_index, group_secret)) in groups.iter().zip(&group_secrets) {
            let mut shares = Vec::with_capacity(spec.count as usize);
            for (member_index, value) in
                split_secret(rng, spec.threshold, spec.count, group_secret)?
            {
                let header = ShareHeader {
                    identifier: self.identifier,
                    extendable: self.extendable,
                    iteration_exponent: self.iteration_exponent,
                    group_index: *group_index,
                    group_threshold,
                    group_count: groups.len() as u8,
                    member_index,
                    member_threshold: spec.threshold,
                };
                shares.push(Share::new(header, value)?);
            }
            out.push(shares);
        }
        Ok(out)
    }

    /// Recover from exactly a threshold number of groups, each holding exactly its member
    /// threshold of shares. Order does not matter and identical duplicates are ignored.
    pub fn recover(shares: &[Share]) -> Result<Self, Error> {
        let mut unique: Vec<&Share> = Vec::new();
        for share in shares {
            if !unique.contains(&share) {
                unique.push(share);
            }
        }
        let first = unique.first().ok_or(Error::Empty)?.header();
        if unique.iter().any(|s| s.header().common() != first.common()) {
            return Err(Error::SetMismatch);
        }
        let mut groups: BTreeMap<u8, Vec<&Share>> = BTreeMap::new();
        for s in &unique {
            groups.entry(s.header().group_index).or_default().push(s);
        }
        if groups.len() != first.group_threshold as usize {
            return Err(Error::WrongGroupCount {
                have: groups.len(),
                need: first.group_threshold as usize,
            });
        }
        let mut group_shares = Vec::with_capacity(groups.len());
        for (&group, members) in &groups {
            let threshold = members[0].header().member_threshold;
            if members
                .iter()
                .any(|s| s.header().member_threshold != threshold)
            {
                return Err(Error::MemberThresholdMismatch { group });
            }
            if members.len() != threshold as usize {
                return Err(Error::WrongMemberCount {
                    group,
                    have: members.len(),
                    need: threshold as usize,
                });
            }
            let points: Vec<(u8, &[u8])> = members
                .iter()
                .map(|s| (s.header().member_index, s.value()))
                .collect();
            group_shares.push((group, recover_secret(threshold, &points)?));
        }
        let points: Vec<(u8, &[u8])> = group_shares
            .iter()
            .map(|(x, y)| (*x, y.as_slice()))
            .collect();
        let ciphertext = recover_secret(first.group_threshold, &points)?;
        Ok(Self {
            identifier: first.identifier,
            extendable: first.extendable,
            iteration_exponent: first.iteration_exponent,
            ciphertext,
        })
    }
}
