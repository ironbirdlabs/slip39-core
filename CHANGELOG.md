# Changelog

Notable changes, by release, in the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
format. Version numbers follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/ironbirdlabs/slip39-core/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/ironbirdlabs/slip39-core/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ironbirdlabs/slip39-core/releases/tag/v0.1.0
