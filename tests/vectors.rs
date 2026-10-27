//! Runs the SLIP-39 test vectors published with trezor/python-shamir-mnemonic.
//! The test asserts that each vector with an expected secret recovers it with passphrase
//! "TREZOR", that each vector without one is rejected with the expected error, and that each
//! accepted mnemonic re-encodes to itself.

use slip39_core::{combine_mnemonics, Error, Share};

/// The error each invalid vector is expected to produce, keyed by its number in the file.
fn expected_error(number: usize) -> Option<Error> {
    Some(match number {
        2 | 21 => Error::Checksum,
        3 | 22 => Error::Padding,
        5 | 24 => Error::WrongMemberCount {
            group: 0,
            have: 1,
            need: 2,
        },
        6 | 7 | 8 | 9 | 25 | 26 | 27 | 28 => Error::SetMismatch,
        10 | 29 => Error::GroupThresholdExceedsCount,
        11 | 30 => Error::DuplicateIndex,
        12 | 31 => Error::MemberThresholdMismatch { group: 0 },
        13 | 32 => Error::Digest,
        14 | 33 => Error::WrongGroupCount { have: 1, need: 2 },
        15 | 34 => Error::WrongGroupCount { have: 1, need: 2 },
        16 | 35 => Error::WrongMemberCount {
            group: 3,
            have: 1,
            need: 2,
        },
        39 => Error::TooFewWords,
        40 => Error::InvalidLength,
        _ => return None,
    })
}

#[test]
fn reference_vectors() {
    let vectors: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("vectors.json")).unwrap();
    assert_eq!(vectors.len(), 45);
    let (mut valid, mut invalid) = (0, 0);
    for v in &vectors {
        let desc = v[0].as_str().unwrap();
        let number: usize = desc.split('.').next().unwrap().parse().unwrap();
        let mnemonics: Vec<&str> = v[1]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m.as_str().unwrap())
            .collect();
        let expected = v[2].as_str().unwrap();
        let result = combine_mnemonics(&mnemonics, b"TREZOR");
        if expected.is_empty() {
            let err = result.expect_err(desc);
            if let Some(want) = expected_error(number) {
                assert_eq!(err, want, "{desc}");
            }
            invalid += 1;
        } else {
            let secret = result.unwrap_or_else(|e| panic!("{desc}: {e}"));
            assert_eq!(hex::encode(&*secret), expected, "{desc}");
            for m in &mnemonics {
                let reencoded = Share::from_mnemonic(m).unwrap().to_mnemonic();
                assert_eq!(reencoded, *m, "{desc}: re-encoding changed the mnemonic");
            }
            valid += 1;
        }
    }
    assert_eq!((valid, invalid), (15, 30));
}
