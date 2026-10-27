# Contributing

Thank you for taking the time. This crate is deliberately small, and most of the rules below
exist to keep it that way.

## Ground rules

- **Match the specification and the reference.** Behaviour follows SLIP-39 and, where the
  specification leaves room, trezor/python-shamir-mnemonic. A change that makes the crate
  disagree with either needs a very good reason, stated in the pull request.
- **Keep dependencies at five.** Each one is part of what a reviewer has to trust. Propose a
  new dependency in an issue before writing code that needs it.
- **One file per algorithm the specification names, one per public type, `lib.rs` for the
  API.** No utility modules; code that lacks a home usually belongs in the caller.
- **The library has no policy.** File handling, prompts, recovery sessions and the like belong
  in applications built on top of it.

## Before opening a pull request

```sh
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
cargo check --no-default-features
tests/interop/run.sh          # needs `pip install shamir-mnemonic`
```

CI runs the same checks, plus a build on the minimum supported Rust version and `cargo deny`.
A change to the share encoding or the cipher should also survive a few minutes of each fuzz
target under `cargo +nightly fuzz run`.

## Releases

Version numbers follow semantic versioning. A release starts from the Release workflow in the
Actions tab, run on `main` with the version as input. The workflow checks that the version
matches `Cargo.toml` and has a `CHANGELOG.md` entry, runs every check, publishes to crates.io,
and then creates the `vX.Y.Z` tag and the GitHub release.
