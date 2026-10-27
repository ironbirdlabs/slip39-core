#![no_main]
//! Generates a share set from fuzz-chosen parameters, then combines a fuzz-chosen and
//! fuzz-mutated subset of it. The harness checks for panics and, when nothing was mutated,
//! that a successful combine returns the original secret.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use slip39_core::{wordlist, GroupSpec};

#[derive(Arbitrary, Debug)]
struct Input {
    secret: Vec<u8>,
    group_threshold: u8,
    groups: Vec<(u8, u8)>,
    passphrase: Vec<u8>,
    extendable: bool,
    picks: Vec<u8>,
    mutations: Vec<(u8, u8, u16)>,
}

fuzz_target!(|input: Input| {
    // Fold the raw parameters into the valid range so generation usually succeeds.
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
    let passphrase: Vec<u8> = input.passphrase.iter().map(|b| 32 + b % 95).take(16).collect();
    let Ok(generated) = slip39_core::generate_mnemonics(group_threshold, &groups, &secret, &passphrase, input.extendable, 0)
    else {
        return;
    };
    let all: Vec<String> = generated.into_iter().flatten().collect();

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

    if let Ok(recovered) = slip39_core::combine_mnemonics(&chosen, &passphrase) {
        if input.mutations.is_empty() {
            assert_eq!(*recovered, secret, "unmutated shares must recover the secret");
        }
    }
});
