# slip39-core

[![CI](https://github.com/ironbirdlabs/slip39-core/actions/workflows/ci.yml/badge.svg)](https://github.com/ironbirdlabs/slip39-core/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/slip39-core.svg)](https://crates.io/crates/slip39-core)
[![docs.rs](https://docs.rs/slip39-core/badge.svg)](https://docs.rs/slip39-core)

A minimal Rust implementation of [SLIP-39](https://github.com/satoshilabs/slips/blob/master/slip-0039.md),
Shamir's Secret Sharing for mnemonic codes. It splits a secret of 16 bytes or more into groups
of word lists and attempts to recover it from a threshold of them. It is intended to follow the
SLIP-39 specification published by SatoshiLabs.

About 750 lines and five dependencies. It includes the two-level group scheme, the passphrase
cipher, and the extendable backup flag.

```toml
[dependencies]
slip39-core = "0.1"
```

## Status

Experimental. On every push, CI runs the 45 test vectors published with the reference
implementation, checks that accepted vectors re-encode to the same words, and exchanges shares
in both directions with Trezor's Python package (see `tests/interop`). Testing of this kind can
show the presence of defects, not their absence.

Keep an independent backup of any secret you process with this software, and rehearse recovery
before relying on it.

## Library

```rust
use slip39_core::GroupSpec;

let secret = [0x42u8; 32];

// Two groups: a 1-of-1 and a 3-of-5. Either group alone is not enough; both are needed.
let groups = [GroupSpec::new(1, 1), GroupSpec::new(3, 5)];
let groups = slip39_core::generate_mnemonics(2, &groups, &secret, b"", true, 1)
    .expect("parameters accepted");
assert_eq!(groups[0].len(), 1);
assert_eq!(groups[1].len(), 5);

// Recover from the single share of group 0 plus any three of group 1.
let picked: Vec<&str> = groups[0].iter().chain(&groups[1][..3]).map(String::as_str).collect();
let recovered = slip39_core::combine_mnemonics(&picked, b"").expect("shares combined");
assert_eq!(*recovered, secret);
```

`generate_mnemonics(group_threshold, groups, secret, passphrase, extendable, iteration_exponent)`
takes a `GroupSpec { threshold, count }` per group and draws randomness from the operating
system. `combine_mnemonics` expects exactly the threshold number of groups, each with exactly
its member threshold of shares; order does not matter, identical duplicates are ignored, and
word case is ignored. The recovered secret is returned in a `Zeroizing<Vec<u8>>`, which attempts
to overwrite its contents when dropped.

Three more things are exposed for callers that need them:

- `Error` is an enum you can match on: which word was invalid, that a checksum failed, that
  shares belong to different sets, how many groups or shares are missing, and so on.
- `generate_mnemonics_with_rng` takes any `RandomSource` you implement, for devices and hosts
  that supply their own randomness. The `getrandom` feature, on by default, provides `OsRandom`.
- `EncryptedSecret` separates the passphrase step from the sharing step, as the specification
  defines them: `encrypt`, `split`, `recover`, `decrypt`. The ciphertext is kept together with
  the identifier, flag and exponent its shares must carry.
- `Share::from_mnemonic` and `Share::to_mnemonic` encode and decode single shares, and
  `wordlist()` exposes the 1024 words.

## Command line

A small example binary exists for scripting and interoperability checks. It does not accept a
secret or a passphrase as a command-line argument, since arguments can be recorded in shell
history and are visible in the process list.

```sh
# Split: the hex secret comes in on stdin, one mnemonic per line goes out.
openssl rand -hex 32 | cargo run -q --example cli -- split 2 1of1 3of5 > shares.txt

# Combine: mnemonics in on stdin, hex secret out.
sed -n '1p;2,4p' shares.txt | cargo run -q --example cli -- combine
```

Add `--passphrase-file PATH` to either command to use a passphrase stored in a file whose
permissions you have restricted, for example with `chmod 600`. Add `--no-ext` to `split` for the
pre-2024 share format.

## Testing

```sh
cargo test                                   # unit tests, README example, 45 reference vectors
tests/interop/run.sh                         # needs `pip install shamir-mnemonic`
cargo +nightly fuzz run decode_words         # needs cargo-fuzz; see fuzz/ for three targets
```

## Versioning

Version numbers follow semantic versioning. While the version is 0.x, a breaking API change
bumps the minor version, with the change noted in `CHANGELOG.md`. The share format is defined
by SLIP-39, not by this crate, so it does not change with the crate version.

## Things to know

- A wrong passphrase does not produce an error. As specified by SLIP-39, it yields a different
  secret that looks like any other. If you use a passphrase, back it up separately from the shares.
- The secret must be at least 16 bytes with an even length. 16 and 32 bytes are the sizes the
  specification requires implementations to support; other sizes may not be accepted by other
  software or devices. Anything larger than 32 bytes would need to be encrypted with a key of
  that size, with the key being what is shared.
- Buffers holding secrets are wrapped in `Zeroizing`, which attempts to overwrite them when
  dropped. This is best effort: it does not cover copies the compiler, allocator or operating
  system may make, swap, core dumps, or the mnemonic strings returned to you.
- The GF(256) multiply is written without lookup tables or data-dependent branches. No claim is
  made that any part of this crate runs in constant time or resists side-channel attacks; the
  digest comparison, for one, is ordinary equality.
- Randomness is requested from the operating system through `getrandom`.
- Requires Rust 1.87 or newer.

## License

Apache-2.0. The word list and test vectors are copied from Trezor's MIT-licensed reference
implementation, as noted in `NOTICE`.
