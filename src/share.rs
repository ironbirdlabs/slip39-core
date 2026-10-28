//! Share mnemonics: the 40-bit header, the zero-padded share value, the checksum, and the
//! encoding of all of it as words from the 1024-word list.

use std::fmt;
use std::sync::OnceLock;

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::rs1024::{self, CHECKSUM_WORDS};
use crate::shamir::MAX_SHARE_COUNT;
use crate::{Error, Secret};

pub(crate) const ID_BITS: u32 = 15;
const EXT_BITS: u32 = 1;
pub(crate) const EXP_BITS: u32 = 4;
const METADATA_WORDS: usize = 2 + 2 + CHECKSUM_WORDS; // id/ext/exp, share params, checksum
const MIN_MNEMONIC_WORDS: usize = METADATA_WORDS + 13; // 13 words hold a 128-bit value
/// The shortest master secret, and therefore share value, the specification allows.
pub(crate) const MIN_SECRET_BYTES: usize = 16;
const WORD_COUNT: usize = 1024;
/// Every word in the list has four to eight ASCII letters.
const WORD_BYTES: usize = 8;

/// The customization string for the checksum, which also selects the cipher salt rule.
pub(crate) fn customization(extendable: bool) -> &'static [u8] {
    if extendable {
        b"shamir_extendable"
    } else {
        b"shamir"
    }
}

/// The 1024-word SLIP-39 word list, in order.
pub fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| include_str!("wordlist.txt").split_whitespace().collect())
}

/// The word list as fixed-width, zero-padded byte arrays, for the lookups below.
fn padded_wordlist() -> &'static [[u8; WORD_BYTES]; WORD_COUNT] {
    static PADDED: OnceLock<[[u8; WORD_BYTES]; WORD_COUNT]> = OnceLock::new();
    PADDED.get_or_init(|| {
        let words = wordlist();
        assert_eq!(words.len(), WORD_COUNT);
        let mut table = [[0u8; WORD_BYTES]; WORD_COUNT];
        for (entry, word) in table.iter_mut().zip(words) {
            entry[..word.len()].copy_from_slice(word.as_bytes());
        }
        table
    })
}

/// The index of `word` in the list, or `None`. Every entry is compared, with a comparison that
/// does not stop at the first differing byte, so the scan does not finish early for words near
/// the front of the list. Case is ignored, as in the reference implementation; the list is ASCII.
fn word_index(word: &str) -> Option<u16> {
    let fits = word.len() <= WORD_BYTES && word.is_ascii();
    let mut probe = [0u8; WORD_BYTES];
    if fits {
        for (p, b) in probe.iter_mut().zip(word.bytes()) {
            *p = b.to_ascii_lowercase();
        }
    }
    let mut index = 0u16;
    let mut found = Choice::from(0);
    for (i, entry) in padded_wordlist().iter().enumerate() {
        let hit = entry[..].ct_eq(&probe[..]);
        index.conditional_assign(&(i as u16), hit);
        found |= hit;
    }
    (fits && bool::from(found)).then_some(index)
}

/// The word at `index`, zero-padded, selected by comparing `index` against every position
/// rather than by indexing the list with it.
fn word_at(index: u16) -> Zeroizing<[u8; WORD_BYTES]> {
    let mut out = Zeroizing::new([0u8; WORD_BYTES]);
    for (i, entry) in padded_wordlist().iter().enumerate() {
        let hit = index.ct_eq(&(i as u16));
        for (o, e) in out.iter_mut().zip(entry) {
            o.conditional_assign(e, hit);
        }
    }
    out
}

/// Pack bytes big-endian into 10-bit words, zero-padded on the left to a word boundary.
fn bytes_to_words(bytes: &[u8]) -> Zeroizing<Vec<u16>> {
    let word_count = (bytes.len() * 8).div_ceil(10);
    let mut words = Zeroizing::new(Vec::with_capacity(word_count));
    let (mut acc, mut nbits) = (0u32, (word_count * 10 - bytes.len() * 8) as u32);
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        nbits += 8;
        while nbits >= 10 {
            nbits -= 10;
            words.push(((acc >> nbits) & 1023) as u16);
        }
        acc &= (1 << nbits) - 1;
    }
    words
}

/// Unpack 10-bit words into bytes, dropping `pad` leading bits, which must be zero.
fn words_to_bytes(words: &[u16], pad: usize) -> Result<Secret, Error> {
    if pad > 0 && words[0] >> (10 - pad) != 0 {
        return Err(Error::Padding);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity((words.len() * 10 - pad) / 8));
    let (mut acc, mut nbits) = (0u32, 0usize);
    for (k, &w) in words.iter().enumerate() {
        acc = (acc << 10) | w as u32;
        nbits += 10 - if k == 0 { pad } else { 0 };
        while nbits >= 8 {
            nbits -= 8;
            bytes.push((acc >> nbits) as u8);
        }
        acc &= (1 << nbits) - 1;
    }
    Ok(bytes)
}

/// The metadata carried by every share. Thresholds and counts are 1-based, indices 0-based.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareHeader {
    /// Random 15-bit value shared by every share of one secret.
    pub identifier: u16,
    /// Whether the share uses the extendable backup format.
    pub extendable: bool,
    /// Scales the PBKDF2 cost of the passphrase cipher as `10000 << e`.
    pub iteration_exponent: u8,
    /// Which group this share belongs to.
    pub group_index: u8,
    /// How many groups are needed to recover the secret.
    pub group_threshold: u8,
    /// How many groups exist.
    pub group_count: u8,
    /// Which member of its group this share is.
    pub member_index: u8,
    /// How many members of its group are needed to recover the group's share.
    pub member_threshold: u8,
}

impl ShareHeader {
    /// The fields every share of one master secret must agree on.
    pub(crate) fn common(&self) -> (u16, bool, u8, u8, u8) {
        (
            self.identifier,
            self.extendable,
            self.iteration_exponent,
            self.group_threshold,
            self.group_count,
        )
    }
}

/// One mnemonic share. Constructed through [`Share::new`] or [`Share::from_mnemonic`], both of
/// which check the header fields and the value length.
///
/// # Example
///
/// ```
/// use slip39_core::Share;
///
/// // The first reference vector: a 128-bit secret with no sharing.
/// let words = "duckling enlarge academic academic agency result length solution fridge \
///              kidney coal piece deal husband erode duke ajar critical decision keyboard";
/// let share = Share::from_mnemonic(words)?;
/// assert_eq!(share.header().group_threshold, 1);
/// assert_eq!(share.header().member_threshold, 1);
/// assert_eq!(share.value().len(), 16);
/// assert_eq!(share.to_mnemonic(), words);
/// # Ok::<(), slip39_core::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    header: ShareHeader,
    value: Secret,
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Share")
            .field("header", &self.header)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Share {
    /// Build a share after checking the header fields and the value length.
    pub fn new(header: ShareHeader, value: impl Into<Secret>) -> Result<Share, Error> {
        let h = header;
        // The group index is checked against the maximum, not against the group count. A share
        // claiming group 7 of 2 is inconsistent, but the reference implementation accepts it,
        // and on input this crate follows the reference rather than being stricter than it.
        let in_range = h.identifier < 1 << ID_BITS
            && h.iteration_exponent < 1 << EXP_BITS
            && h.group_index < MAX_SHARE_COUNT
            && h.member_index < MAX_SHARE_COUNT
            && [h.group_threshold, h.group_count, h.member_threshold]
                .iter()
                .all(|v| (1..=MAX_SHARE_COUNT).contains(v));
        if !in_range {
            return Err(Error::InvalidHeader);
        }
        if h.group_count < h.group_threshold {
            return Err(Error::GroupThresholdExceedsCount);
        }
        let value = value.into();
        if value.len() < MIN_SECRET_BYTES || !value.len().is_multiple_of(2) {
            return Err(Error::InvalidValueLength);
        }
        Ok(Share { header, value })
    }

    /// The share's metadata.
    pub fn header(&self) -> ShareHeader {
        self.header
    }

    /// The share's value: this member's point on the group's polynomials.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Encode as a space-separated mnemonic.
    pub fn to_mnemonic(&self) -> String {
        let h = self.header;
        let id_exp = (h.identifier as u32) << (EXT_BITS + EXP_BITS)
            | (h.extendable as u32) << EXP_BITS
            | h.iteration_exponent as u32;
        let params = (h.group_index as u32) << 16
            | ((h.group_threshold - 1) as u32) << 12
            | ((h.group_count - 1) as u32) << 8
            | (h.member_index as u32) << 4
            | (h.member_threshold - 1) as u32;
        let value_words = bytes_to_words(&self.value);
        let mut data = Zeroizing::new(Vec::with_capacity(4 + value_words.len() + CHECKSUM_WORDS));
        data.extend([
            (id_exp >> 10) as u16,
            (id_exp & 1023) as u16,
            (params >> 10) as u16,
            (params & 1023) as u16,
        ]);
        data.extend(value_words.iter().copied());
        let checksum = rs1024::checksum(&data, customization(h.extendable));
        data.extend(checksum);
        // Build the string directly rather than through a temporary vector of word pointers,
        // which would be freed without being overwritten. Words are at most 8 letters, so the
        // capacity is intended to avoid reallocation.
        let mut out = String::with_capacity(data.len() * (WORD_BYTES + 1));
        for (k, &i) in data.iter().enumerate() {
            if k > 0 {
                out.push(' ');
            }
            let word = word_at(i);
            let len = word.iter().position(|&b| b == 0).unwrap_or(WORD_BYTES);
            out.push_str(std::str::from_utf8(&word[..len]).expect("the word list is ASCII"));
        }
        out
    }

    /// Decode a mnemonic, checking its checksum and structure. Word case is ignored.
    pub fn from_mnemonic(mnemonic: &str) -> Result<Share, Error> {
        let mut data = Zeroizing::new(Vec::with_capacity(mnemonic.split_whitespace().count()));
        for (position, word) in mnemonic.split_whitespace().enumerate() {
            data.push(word_index(word).ok_or(Error::InvalidWord { position })?);
        }
        if data.len() < MIN_MNEMONIC_WORDS {
            return Err(Error::TooFewWords);
        }
        let pad = (10 * (data.len() - METADATA_WORDS)) % 16;
        if pad > 8 {
            return Err(Error::InvalidLength);
        }
        let id_exp = (data[0] as u32) << 10 | data[1] as u32;
        let extendable = (id_exp >> EXP_BITS) & 1 == 1;
        if !rs1024::verify(&data, customization(extendable)) {
            return Err(Error::Checksum);
        }
        let params = (data[2] as u32) << 10 | data[3] as u32;
        let nibble = |shift: u32| ((params >> shift) & 15) as u8;
        let header = ShareHeader {
            identifier: (id_exp >> (EXT_BITS + EXP_BITS)) as u16,
            extendable,
            iteration_exponent: (id_exp & ((1 << EXP_BITS) - 1)) as u8,
            group_index: nibble(16),
            group_threshold: nibble(12) + 1,
            group_count: nibble(8) + 1,
            member_index: nibble(4),
            member_threshold: nibble(0) + 1,
        };
        let value = words_to_bytes(&data[4..data.len() - CHECKSUM_WORDS], pad)?;
        Share::new(header, value) // validates the header, including threshold vs count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_packing_round_trips_at_both_standard_sizes() {
        for len in [16usize, 32] {
            let bytes: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37) ^ 0x5a).collect();
            let words = bytes_to_words(&bytes);
            assert_eq!(words.len(), (len * 8).div_ceil(10));
            let pad = words.len() * 10 - len * 8;
            assert_eq!(*words_to_bytes(&words, pad).unwrap(), bytes);
        }
    }

    #[test]
    fn nonzero_padding_is_rejected() {
        let mut words = bytes_to_words(&[0u8; 16]);
        let pad = words.len() * 10 - 128;
        words[0] |= 1 << (10 - pad); // set the lowest padding bit
        assert_eq!(words_to_bytes(&words, pad), Err(Error::Padding));
    }

    #[test]
    fn word_lookup_agrees_with_the_list_in_both_directions() {
        for (i, &word) in wordlist().iter().enumerate() {
            assert_eq!(word_index(word), Some(i as u16), "{word}");
            assert_eq!(word_index(&word.to_ascii_uppercase()), Some(i as u16));
            let padded = word_at(i as u16);
            assert_eq!(&padded[..word.len()], word.as_bytes());
            assert!(padded[word.len()..].iter().all(|&b| b == 0));
        }
        for missing in ["", "zzz", "academics", "acadèmic", "123", "a b"] {
            assert_eq!(word_index(missing), None, "{missing:?}");
        }
    }
}
