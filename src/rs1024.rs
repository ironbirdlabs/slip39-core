//! The RS1024 checksum: a Reed-Solomon code over GF(1024) that appends three words. The
//! specification states that it detects any error touching up to three words.

/// Words the checksum occupies at the end of a mnemonic.
pub(crate) const CHECKSUM_WORDS: usize = 3;

fn polymod(values: impl IntoIterator<Item = u32>) -> u32 {
    const GEN: [u32; 10] = [
        0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009, 0x1C0C2412, 0x38086C24, 0x3090FC48,
        0x21B1F890, 0x3F3F120,
    ];
    let mut chk = 1u32;
    for v in values {
        let b = chk >> 20;
        chk = ((chk & 0xFFFFF) << 10) ^ v;
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn values<'a>(customization: &'a [u8], data: &'a [u16]) -> impl Iterator<Item = u32> + 'a {
    customization
        .iter()
        .map(|&c| c as u32)
        .chain(data.iter().map(|&d| d as u32))
}

/// The three checksum words for `data` under `customization`.
pub(crate) fn checksum(data: &[u16], customization: &[u8]) -> [u16; CHECKSUM_WORDS] {
    let pm = polymod(values(customization, data).chain([0; CHECKSUM_WORDS])) ^ 1;
    [
        (pm >> 20) as u16 & 1023,
        (pm >> 10) as u16 & 1023,
        pm as u16 & 1023,
    ]
}

/// Whether `data`, which ends with its checksum words, verifies under `customization`.
pub(crate) fn verify(data: &[u16], customization: &[u8]) -> bool {
    polymod(values(customization, data)) == 1
}
