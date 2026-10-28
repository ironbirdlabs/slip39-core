# Changelog

Notable changes, by release, in the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
format. Version numbers follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/ironbirdlabs/slip39-core/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/ironbirdlabs/slip39-core/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ironbirdlabs/slip39-core/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ironbirdlabs/slip39-core/releases/tag/v0.1.0
