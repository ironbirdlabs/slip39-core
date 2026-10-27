//! Black-box tests of the public API: round trips, parameter validation, randomness injection,
//! the encrypted-secret layers, and share construction.

use slip39_core::{
    combine_mnemonics, generate_mnemonics, generate_mnemonics_with_rng, EncryptedSecret, Error,
    GroupSpec, RandomSource, Share, ShareHeader,
};

/// A deterministic source for tests: a counter fed through a simple mixer.
struct Fixed(u64);

impl RandomSource for Fixed {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        for b in buf {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (self.0 >> 56) as u8;
        }
        Ok(())
    }
}

struct Failing;

impl RandomSource for Failing {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::Random)
    }
}

fn g(threshold: u8, count: u8) -> GroupSpec {
    GroupSpec::new(threshold, count)
}

#[test]
fn group_round_trip() {
    let secret: Vec<u8> = (0..32).collect();
    for extendable in [false, true] {
        let groups = [g(1, 1), g(1, 1), g(3, 5), g(2, 6)];
        let m = generate_mnemonics(2, &groups, &secret, b"TREZOR", extendable, 0).unwrap();
        assert_eq!(m.iter().map(Vec::len).collect::<Vec<_>>(), [1, 1, 5, 6]);

        // Three of group 2 plus two of group 3.
        let pick: Vec<&str> = m[2][..3]
            .iter()
            .chain(&m[3][..2])
            .map(String::as_str)
            .collect();
        assert_eq!(*combine_mnemonics(&pick, b"TREZOR").unwrap(), secret);
        // A wrong passphrase decrypts to a different secret without error, per the spec.
        assert_ne!(*combine_mnemonics(&pick, b"wrong").unwrap(), secret);
        // Group 0 plus the last two of group 3, with one mnemonic repeated.
        let pick: Vec<&str> = m[0]
            .iter()
            .chain(&m[3][4..])
            .chain(&m[0])
            .map(String::as_str)
            .collect();
        assert_eq!(*combine_mnemonics(&pick, b"TREZOR").unwrap(), secret);
        // One complete group is not enough.
        let pick: Vec<&str> = m[2].iter().map(String::as_str).collect();
        assert_eq!(
            combine_mnemonics(&pick, b"TREZOR"),
            Err(Error::WrongGroupCount { have: 1, need: 2 })
        );
        // Too few members in a group.
        let pick: Vec<&str> = m[2][..2]
            .iter()
            .chain(&m[3][..2])
            .map(String::as_str)
            .collect();
        assert_eq!(
            combine_mnemonics(&pick, b"TREZOR"),
            Err(Error::WrongMemberCount {
                group: 2,
                have: 2,
                need: 3
            })
        );
    }
}

#[test]
fn rejects_bad_parameters() {
    let s = [7u8; 16];
    let gen = |t, groups: &[GroupSpec], secret: &[u8], pass: &[u8], e| {
        generate_mnemonics(t, groups, secret, pass, true, e)
    };
    assert_eq!(
        gen(1, &[g(1, 2)], &s, b"", 0),
        Err(Error::InvalidGroup { group: 0 })
    );
    assert_eq!(gen(2, &[g(1, 1)], &s, b"", 0), Err(Error::InvalidGroups));
    assert_eq!(
        gen(1, &[g(2, 1)], &s, b"", 0),
        Err(Error::InvalidGroup { group: 0 })
    );
    assert_eq!(
        gen(1, &[g(1, 1), g(3, 2)], &s, b"", 0),
        Err(Error::InvalidGroup { group: 1 })
    );
    assert_eq!(
        gen(1, &[g(1, 1)], &s[..15], b"", 0),
        Err(Error::InvalidSecretLength)
    );
    assert_eq!(
        gen(1, &[g(1, 1)], &[7u8; 17], b"", 0),
        Err(Error::InvalidSecretLength)
    );
    assert_eq!(
        gen(1, &[g(1, 1)], &s, b"caf\xc3\xa9", 0),
        Err(Error::InvalidPassphrase)
    );
    assert_eq!(gen(1, &[g(1, 1)], &s, b"", 16), Err(Error::InvalidExponent));
    assert_eq!(gen(1, &[], &s, b"", 0), Err(Error::InvalidGroups));
}

#[test]
fn injected_randomness_is_deterministic_and_fallible() {
    let secret = [9u8; 16];
    let a =
        generate_mnemonics_with_rng(1, &[g(2, 3)], &secret, b"", true, 0, &mut Fixed(1)).unwrap();
    let b =
        generate_mnemonics_with_rng(1, &[g(2, 3)], &secret, b"", true, 0, &mut Fixed(1)).unwrap();
    let c =
        generate_mnemonics_with_rng(1, &[g(2, 3)], &secret, b"", true, 0, &mut Fixed(2)).unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(*combine_mnemonics(&a[0][1..], b"").unwrap(), secret);
    assert_eq!(
        generate_mnemonics_with_rng(1, &[g(2, 3)], &secret, b"", true, 0, &mut Failing),
        Err(Error::Random)
    );
}

#[test]
fn encrypted_secret_layers() {
    let secret = [0xabu8; 32];
    let mut rng = Fixed(7);
    let encrypted = EncryptedSecret::encrypt(&secret, b"pass", true, 0, &mut rng).unwrap();
    assert!(encrypted.identifier() < 1 << 15);
    assert!(encrypted.extendable());
    assert_eq!(encrypted.iteration_exponent(), 0);
    assert_eq!(*encrypted.decrypt(b"pass"), secret);
    assert_ne!(*encrypted.decrypt(b"nope"), secret);

    // Shares carry the encrypted secret's parameters, and recover reproduces it exactly.
    let groups = encrypted.split(2, &[g(2, 3), g(1, 1)], &mut rng).unwrap();
    for share in groups.iter().flatten() {
        let h = share.header();
        assert_eq!(
            (h.identifier, h.extendable, h.iteration_exponent),
            (encrypted.identifier(), true, 0)
        );
    }
    let picked: Vec<Share> = groups[0][..2].iter().chain(&groups[1]).cloned().collect();
    let recovered = EncryptedSecret::recover(&picked).unwrap();
    assert_eq!(recovered, encrypted);
    assert_eq!(*recovered.decrypt(b"pass"), secret);
    assert_eq!(EncryptedSecret::recover(&[]), Err(Error::Empty));
    assert!(
        !format!("{encrypted:?}").contains("ab, ab"),
        "ciphertext must be redacted in Debug"
    );
}

#[test]
fn word_lookup_ignores_case_and_reports_position() {
    let share = Share::new(
        ShareHeader {
            identifier: 1,
            extendable: true,
            iteration_exponent: 0,
            group_index: 0,
            group_threshold: 1,
            group_count: 1,
            member_index: 0,
            member_threshold: 1,
        },
        vec![3u8; 16],
    )
    .unwrap();
    let lower = share.to_mnemonic();
    let shouting = lower.to_ascii_uppercase();
    assert_ne!(lower, shouting);
    assert_eq!(Share::from_mnemonic(&shouting).unwrap(), share);
    assert_eq!(
        Share::from_mnemonic(&shouting).unwrap().to_mnemonic(),
        lower
    );

    let mut words: Vec<&str> = lower.split(' ').collect();
    words[5] = "notaword";
    assert_eq!(
        Share::from_mnemonic(&words.join(" ")),
        Err(Error::InvalidWord { position: 5 })
    );
}

#[test]
fn share_constructor_validates() {
    let ok = ShareHeader {
        identifier: 0x7FFF,
        extendable: true,
        iteration_exponent: 15,
        group_index: 15,
        group_threshold: 16,
        group_count: 16,
        member_index: 15,
        member_threshold: 16,
    };
    let share = Share::new(ok, vec![9u8; 32]).unwrap();
    let decoded = Share::from_mnemonic(&share.to_mnemonic()).unwrap();
    assert_eq!(decoded, share);
    assert_eq!(decoded.header(), ok);
    assert_eq!(decoded.value(), &[9u8; 32][..]);
    assert!(
        !format!("{share:?}").contains("9, 9"),
        "value must be redacted in Debug"
    );

    let bad = [
        ShareHeader {
            identifier: 0x8000,
            ..ok
        },
        ShareHeader {
            iteration_exponent: 16,
            ..ok
        },
        ShareHeader {
            group_index: 16,
            ..ok
        },
        ShareHeader {
            member_index: 16,
            ..ok
        },
        ShareHeader {
            group_threshold: 0,
            ..ok
        },
        ShareHeader {
            group_count: 17,
            ..ok
        },
        ShareHeader {
            member_threshold: 0,
            ..ok
        },
    ];
    for h in bad {
        assert_eq!(
            Share::new(h, vec![9u8; 32]),
            Err(Error::InvalidHeader),
            "{h:?}"
        );
    }
    assert_eq!(
        Share::new(
            ShareHeader {
                group_threshold: 3,
                group_count: 2,
                ..ok
            },
            vec![9u8; 32]
        ),
        Err(Error::GroupThresholdExceedsCount)
    );
    assert_eq!(
        Share::new(ok, vec![9u8; 15]),
        Err(Error::InvalidValueLength)
    );
    assert_eq!(
        Share::new(ok, vec![9u8; 17]),
        Err(Error::InvalidValueLength)
    );
}
