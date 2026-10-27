#![no_main]
//! Well-formed word sequences, with a valid checksum when the first byte's low bit is set, so
//! the fuzzer reaches the length, padding, header and value logic behind the checksum gate.
//! The harness checks that anything that decodes re-encodes to exactly the input.

use libfuzzer_sys::fuzz_target;
use slip39_core::fuzz_hooks::checksum;
use slip39_core::wordlist;

fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else { return };
    let words = wordlist();
    let mut indices: Vec<u16> = rest
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]) % 1024)
        .collect();
    if flags & 1 == 1 && indices.len() > 3 {
        let extendable = (indices[1] >> 4) & 1 == 1;
        let n = indices.len() - 3;
        let fixed = checksum(&indices[..n], extendable);
        indices[n..].copy_from_slice(&fixed);
    }
    let mnemonic = indices.iter().map(|&i| words[i as usize]).collect::<Vec<_>>().join(" ");
    if let Ok(share) = slip39_core::Share::from_mnemonic(&mnemonic) {
        assert_eq!(share.to_mnemonic(), mnemonic, "decode then encode must reproduce the input");
    }
});
