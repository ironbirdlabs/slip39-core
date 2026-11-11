#![no_main]
//! Raw bytes straight into the decoder. The harness checks that the decoder returns an error
//! rather than panicking, that anything it accepts is its own encoding once case and the amount
//! of whitespace are set aside, and that the encoding decodes to the same share.
//!
//! Random bytes do not get past the word list and the checksum, so the corpus needs real
//! mnemonics to start from. CI seeds it from `tests/vectors.json`; see the fuzz job in
//! `.github/workflows/ci.yml` for the command.

use libfuzzer_sys::fuzz_target;
use slip39_core::Share;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(share) = Share::from_mnemonic(text) {
            let encoded = share.to_mnemonic();
            let normalized = text.split_whitespace().map(str::to_ascii_lowercase).collect::<Vec<_>>().join(" ");
            assert_eq!(encoded, normalized, "an accepted mnemonic must be its own encoding");
            let again = Share::from_mnemonic(&encoded).expect("re-encoded share must decode");
            assert_eq!(again, share);
        }
    }
});
