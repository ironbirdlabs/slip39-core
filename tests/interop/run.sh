#!/usr/bin/env bash
# Exchanges shares with Trezor's reference implementation in both directions: five fixed cases,
# then ROUNDS (default 50) randomized ones; SEED repeats a particular randomized run.
# Needs the Python package `shamir-mnemonic` importable by $PYTHON (default: python3).
set -euo pipefail
cd "$(dirname "$0")/../.."

PYTHON="${PYTHON:-python3}"
cargo build --example cli --quiet
CLI=target/debug/examples/cli
REF="$PYTHON -I tests/interop/interop.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
printf 'pw' > "$WORK/pw"

hex() { "$PYTHON" -c "import secrets; print(secrets.token_hex($1))"; }
pass=0
fail=0
check() {
    if [ "$2" = "$3" ]; then
        echo "PASS  $1"; pass=$((pass + 1))
    else
        echo "FAIL  $1 (expected $3, got $2)"; fail=$((fail + 1))
    fi
}

S=$(hex 32); echo "$S" | $CLI split 2 1of1 3of5 2of6 --passphrase-file "$WORK/pw" > "$WORK/a"
check "Rust split -> reference combine, 256-bit, extendable, two groups, passphrase" \
    "$(sed -n '1p;2,4p' "$WORK/a" | $REF combine pw)" "$S"

S=$(hex 16); echo "$S" | $CLI split 1 3of5 --no-ext > "$WORK/b"
check "Rust split -> reference combine, 128-bit, non-extendable" \
    "$(sed -n '2p;3p;5p' "$WORK/b" | $REF combine '')" "$S"

S=$(hex 32); $REF generate "$S" 2 pw 1 1 2of3 3of5 1of1 > "$WORK/c"
check "reference generate -> Rust combine, exponent 1, two groups, passphrase" \
    "$(sed -n '1,2p;9p' "$WORK/c" | $CLI combine --passphrase-file "$WORK/pw")" "$S"
check "reference generate -> Rust combine, upper-cased words" \
    "$(sed -n '4,6p;9p' "$WORK/c" | tr 'a-z' 'A-Z' | $CLI combine --passphrase-file "$WORK/pw")" "$S"

S=$(hex 16); $REF generate "$S" 1 '' 0 0 2of2 > "$WORK/d"
check "reference generate -> Rust combine, 128-bit, non-extendable, 2of2" \
    "$($CLI combine < "$WORK/d")" "$S"

if "$PYTHON" -I tests/interop/random_rounds.py "$CLI" "${ROUNDS:-50}" ${SEED:+"$SEED"}; then
    pass=$((pass + 1))
else
    fail=$((fail + 1))
fi

echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
