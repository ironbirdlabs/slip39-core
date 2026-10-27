//! The error type.

use std::fmt;

/// Why an operation was rejected. Group numbers in the data fields are zero-based group
/// indices, as carried in share headers. New variants may be added in minor releases.
///
/// # Example
///
/// ```
/// use slip39_core::{combine_mnemonics, Error, Share};
///
/// // A word that is not in the list is reported with its position.
/// let typo = "duckling enlarge academic academic agency result length solution fridge \
///             kidney coal piece deal husband erode duke ajar critical decision zebra";
/// match Share::from_mnemonic(typo) {
///     Err(Error::InvalidWord { position }) => assert_eq!(position, 19),
///     other => panic!("unexpected: {other:?}"),
/// }
///
/// // One share of a 2-of-3 set: recovery says exactly what is missing.
/// let one = "shadow pistol academic always adequate wildlife fancy gross oasis cylinder \
///            mustang wrist rescue view short owner flip making coding armed";
/// match combine_mnemonics(&[one], b"") {
///     Err(Error::WrongMemberCount { group, have, need }) => {
///         assert_eq!((group, have, need), (0, 1, 2));
///     }
///     other => panic!("unexpected: {other:?}"),
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A word is not in the word list.
    InvalidWord {
        /// Zero-based index of the word within the mnemonic.
        position: usize,
    },
    /// A mnemonic has fewer than 20 words.
    TooFewWords,
    /// A mnemonic's word count cannot encode a share.
    InvalidLength,
    /// A mnemonic's checksum does not match.
    Checksum,
    /// A mnemonic's padding bits are not zero.
    Padding,
    /// A share header field is out of range.
    InvalidHeader,
    /// A share's group threshold exceeds its group count.
    GroupThresholdExceedsCount,
    /// A share value is shorter than 16 bytes or has an odd length.
    InvalidValueLength,
    /// No shares were given.
    Empty,
    /// Shares differ in identifier, extendable flag, iteration exponent, group threshold or
    /// group count, so they belong to different sets.
    SetMismatch,
    /// The wrong number of groups was given.
    WrongGroupCount {
        /// Groups given.
        have: usize,
        /// Groups required, exactly.
        need: usize,
    },
    /// Shares of one group disagree on the member threshold.
    MemberThresholdMismatch {
        /// Zero-based index of the group.
        group: u8,
    },
    /// The wrong number of shares was given for a group.
    WrongMemberCount {
        /// Zero-based index of the group.
        group: u8,
        /// Shares given for the group.
        have: usize,
        /// Shares required for the group, exactly.
        need: usize,
    },
    /// Two shares in one group carry the same member index.
    DuplicateIndex,
    /// Share values differ in length.
    ValueLengthMismatch,
    /// The recovered digest does not match, which usually means a share is wrong or corrupted.
    Digest,
    /// The secret is shorter than 16 bytes or has an odd length.
    InvalidSecretLength,
    /// The passphrase contains bytes outside printable ASCII.
    InvalidPassphrase,
    /// The iteration exponent is above 15.
    InvalidExponent,
    /// There are no groups, more than 16, or the group threshold is not between 1 and the
    /// number of groups.
    InvalidGroups,
    /// A group has a member count outside 1 to 16, a threshold outside 1 to its count, or a
    /// threshold of 1 with more than one member.
    InvalidGroup {
        /// Zero-based index of the group.
        group: u8,
    },
    /// The random source failed.
    Random,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidWord { position } => {
                write!(f, "word {} is not in the word list", position + 1)
            }
            Error::TooFewWords => f.write_str("fewer than 20 words"),
            Error::InvalidLength => f.write_str("invalid mnemonic length"),
            Error::Checksum => f.write_str("invalid checksum"),
            Error::Padding => f.write_str("invalid padding"),
            Error::InvalidHeader => f.write_str("share header field out of range"),
            Error::GroupThresholdExceedsCount => f.write_str("group threshold exceeds group count"),
            Error::InvalidValueLength => f.write_str("invalid share value length"),
            Error::Empty => f.write_str("no shares"),
            Error::SetMismatch => f.write_str("shares are from different sets"),
            Error::WrongGroupCount { have, need } => {
                write!(f, "need exactly {need} groups, got {have}")
            }
            Error::MemberThresholdMismatch { group } => {
                write!(f, "member thresholds differ in group {}", group + 1)
            }
            Error::WrongMemberCount { group, have, need } => {
                write!(
                    f,
                    "group {} needs exactly {need} shares, got {have}",
                    group + 1
                )
            }
            Error::DuplicateIndex => f.write_str("duplicate share index"),
            Error::ValueLengthMismatch => f.write_str("share values differ in length"),
            Error::Digest => f.write_str("digest mismatch"),
            Error::InvalidSecretLength => f.write_str("invalid secret length"),
            Error::InvalidPassphrase => f.write_str("passphrase is not printable ASCII"),
            Error::InvalidExponent => f.write_str("iteration exponent above 15"),
            Error::InvalidGroups => f.write_str("invalid group count or group threshold"),
            Error::InvalidGroup { group } => {
                write!(f, "invalid threshold or count for group {}", group + 1)
            }
            Error::Random => f.write_str("random source failed"),
        }
    }
}

impl std::error::Error for Error {}
