# Changelog

Notable changes, by release, in the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
format. Version numbers follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.3] - 2026-11-11

Follow-ups from a second review. No change to the share format or the public API.

- Fixed: a word followed by zero bytes, such as `"acid\0"`, was accepted as the word itself,
  because the lookup table pads short words with zero bytes. Words must now consist of ASCII
  letters, as the reference implementation requires. The share decoded from such input was the
  one the words spelled, so no wrong secret could result.
- The RS1024 checksum is computed with masks rather than branches that depend on the share
  value.
- `Share::new` wraps the value before it checks the header, so a value passed as a plain
  `Vec<u8>` is overwritten when the header is rejected too.
- `cargo test --no-default-features` builds and passes, and CI runs it in place of
  `cargo check`: the tests take their randomness from a fixed source, the documentation
  examples that draw from the operating system are compiled only with the `getrandom` feature,
  and the CLI example requires that feature.
- A second randomized differential test against the reference implementation,
  `tests/interop/rejection_rounds.py`, run by `tests/interop/run.sh`: it compares which
  malformed mnemonics and which selections of shares each of the two rejects. The CLI example
  gains a `decode` command for it.
- Fuzzing: `decode_raw` checks that an accepted mnemonic is its own encoding, and CI seeds its
  corpus from the reference vectors; `combine` no longer runs the passphrase cipher on every
  execution, and takes its randomness from the input so that a failure can be replayed.
- The release workflow runs its checks in a job that holds no credentials; only a second job,
  which publishes, tags and releases, can obtain a crates.io token or write to the repository.
- `fuzz/Cargo.lock` is current again, and CI checks that it stays so.
- Documentation: the reference implementation tested against is 0.3.0, not 0.3.1, and the
  dependency count in `CONTRIBUTING.md` is six.

## [0.1.2] - 2026-10-28

Follow-ups from an outside review. No change to the share format or the public API.

- `combine_mnemonics` documents that the shares decide the key-derivation cost, up to
  `10000 << 15` iterations, with an example that checks the exponent through
  `EncryptedSecret` before decrypting.
- Word lookup during decoding compares every list entry with a constant-time comparison rather
  than stopping at the first match, encoding selects each word the same way, and the digest
  check uses a constant-time comparison.
- `Share::new` records why a group index is not checked against the group count: the
  reference implementation accepts such shares, and this crate follows it on input.
- A randomized differential test against the reference implementation, run by
  `tests/interop/run.sh` and so on every CI build: random secret sizes, group structures,
  passphrases, flags and exponents, in both directions.
- The CLI example takes `--exponent`.
- CI actions pinned to commit hashes, as the release workflow's already were.

## [0.1.1] - 2026-10-27

Documentation only; no change to the code.

- A complete example on the crate's front page, and examples of implementing `RandomSource`
  and matching on `Error`, all run as tests.
- A "Choosing parameters" section in the README, and a link to keyshard as a worked
  application.

## [0.1.0] - 2026-10-27

First release.

- SLIP-39 generation and recovery with the two-level group scheme, the passphrase cipher and
  the extendable backup flag.
- `EncryptedSecret` for the passphrase and sharing layers separately; `Share` for single
  mnemonics; `GroupSpec` for group parameters.
- `RandomSource` for caller-supplied randomness, with `OsRandom` behind the default `getrandom`
  feature.
- An `Error` enum with a variant per rejection reason.
- Tests: the 45 reference vectors with expected error variants, black-box API tests, a two-way
  interoperability check against the reference Python implementation, and three fuzz targets.

[Unreleased]: https://github.com/ironbirdlabs/slip39-core/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/ironbirdlabs/slip39-core/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/ironbirdlabs/slip39-core/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ironbirdlabs/slip39-core/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ironbirdlabs/slip39-core/releases/tag/v0.1.0
