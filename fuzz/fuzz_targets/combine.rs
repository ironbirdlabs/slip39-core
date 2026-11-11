#![no_main]
//! Splits a fuzz-chosen value under fuzz-chosen parameters, then recovers from a fuzz-chosen
//! and fuzz-mutated selection of the resulting mnemonics. The harness checks for panics, that
//! parameters within the specification's limits are accepted, and, when nothing was mutated,
//! that a successful recovery returns the value that was split.
//!
//! The passphrase cipher is left out. It would add two PBKDF2 runs to every execution, and it
//! has no input-dependent paths for a fuzzer to find; the reference vectors and the
//! interoperability check cover it. The value is therefore planted as the encrypted secret
//! directly, through a 1-of-1 share. Randomness is derived from the input, so that an input
//! that fails once fails again when replayed.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use slip39_core::{wordlist, EncryptedSecret, Error, GroupSpec, RandomSource, Share, ShareHeader};

#[derive(Arbitrary, Debug)]
struct Input {
    secret: Vec<u8>,
    identifier: u16,
    extendable: bool,
    iteration_exponent: u8,
    group_threshold: u8,
    groups: Vec<(u8, u8)>,
    seed: u64,
    picks: Vec<u8>,
    mutations: Vec<(u8, u8, u16)>,
}

/// A deterministic source seeded by the input: a counter fed through a simple mixer.
struct Seeded(u64);

impl RandomSource for Seeded {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        for b in buf {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (self.0 >> 56) as u8;
        }
        Ok(())
    }
}

fuzz_target!(|input: Input| {
    // Fold the raw parameters into the valid range, so that the split has to succeed.
    let mut secret = input.secret;
    secret.resize(16 + 2 * (secret.len() % 9), 0x5a); // 16 to 32 bytes, even
    let mut groups: Vec<GroupSpec> = input
        .groups
        .iter()
        .take(16)
        .map(|&(t, n)| {
            let n = n % 16 + 1;
            let t = t % n + 1;
            if t == 1 { GroupSpec::new(1, 1) } else { GroupSpec::new(t, n) }
        })
        .collect();
    if groups.is_empty() {
        groups.push(GroupSpec::new(2, 3));
    }
    let group_threshold = input.group_threshold % groups.len() as u8 + 1;

    // The encrypted secret, planted through a 1-of-1 share rather than derived from a passphrase.
    let planted = ShareHeader {
        identifier: input.identifier % (1 << 15),
        extendable: input.extendable,
        iteration_exponent: input.iteration_exponent % 16,
        group_index: 0,
        group_threshold: 1,
        group_count: 1,
        member_index: 0,
        member_threshold: 1,
    };
    let encrypted = Share::new(planted, secret)
        .and_then(|share| EncryptedSecret::recover(&[share]))
        .expect("a 1-of-1 share must recover");
    let split = encrypted
        .split(group_threshold, &groups, &mut Seeded(input.seed))
        .expect("parameters within the limits must be accepted");
    let all: Vec<String> = split.iter().flatten().map(Share::to_mnemonic).collect();

    let mut chosen: Vec<String> = input.picks.iter().take(40).map(|&p| all[p as usize % all.len()].clone()).collect();
    let words = wordlist();
    for &(kind, which, arg) in input.mutations.iter().take(8) {
        if chosen.is_empty() {
            break;
        }
        let i = which as usize % chosen.len();
        match kind % 4 {
            0 => {
                // Replace one word.
                let mut w: Vec<&str> = chosen[i].split(' ').collect();
                let j = arg as usize % w.len();
                w[j] = words[(arg as usize / w.len()) % words.len()];
                chosen[i] = w.join(" ");
            }
            1 => chosen.push(chosen[i].clone()), // duplicate a mnemonic
            2 => {
                // Truncate a mnemonic.
                let keep = arg as usize % chosen[i].split(' ').count();
                chosen[i] = chosen[i].split(' ').take(keep).collect::<Vec<_>>().join(" ");
            }
            _ => {
                chosen.remove(i);
            }
        }
    }

    let recovered = chosen
        .iter()
        .map(|m| Share::from_mnemonic(m))
        .collect::<Result<Vec<Share>, Error>>()
        .and_then(|shares| EncryptedSecret::recover(&shares));
    if let Ok(recovered) = recovered {
        if input.mutations.is_empty() {
            assert_eq!(recovered, encrypted, "unmutated shares must recover what was split");
        }
    }
});
