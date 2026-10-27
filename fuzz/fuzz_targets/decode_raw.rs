#![no_main]
//! Raw bytes straight into the decoder. The harness checks that the decoder returns an error
//! rather than panicking, and that anything it accepts survives an encode-decode round trip.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(share) = slip39_core::Share::from_mnemonic(text) {
            let again = slip39_core::Share::from_mnemonic(&share.to_mnemonic()).expect("re-encoded share must decode");
            assert_eq!(again, share);
        }
    }
});
