"""Randomized differential test against Trezor's reference package, in both directions.

  random_rounds.py <cli> <rounds> [seed]

Each round draws a secret size, a group structure, a passphrase, the extendable flag and an
iteration exponent at random, then checks that shares made by this crate's CLI are recovered
by the reference, and that shares made by the reference are recovered by the CLI, each from a
random threshold-sized selection of groups and members. The seed is printed so that a failing
run can be repeated.
"""

import os
import random
import secrets
import subprocess
import sys
import tempfile

from shamir_mnemonic import combine_mnemonics, generate_mnemonics

cli = sys.argv[1]
rounds = int(sys.argv[2])
seed = int(sys.argv[3]) if len(sys.argv) > 3 else secrets.randbits(32)
rng = random.Random(seed)
print(f"random rounds: seed={seed} rounds={rounds}")


def structure():
    """A group threshold and (threshold, count) per group, within the specification's limits:
    counts up to 16, and a group with threshold 1 holds exactly one member."""
    group_count = rng.randint(1, 4)
    group_threshold = rng.randint(1, group_count)
    groups = []
    for _ in range(group_count):
        count = rng.randint(1, 16) if rng.random() < 0.2 else rng.randint(1, 6)
        threshold = 1 if count == 1 else rng.randint(2, count)
        groups.append((threshold, count))
    return group_threshold, groups


def selection(group_threshold, groups, mnemonics):
    """Exactly `group_threshold` groups, each contributing exactly its threshold, shuffled."""
    picked = []
    for g in rng.sample(range(len(groups)), group_threshold):
        picked += rng.sample(mnemonics[g], groups[g][0])
    rng.shuffle(picked)
    return picked


def run_cli(args, stdin_text, passphrase_file):
    if passphrase_file:
        args = args + ["--passphrase-file", passphrase_file]
    done = subprocess.run([cli] + args, input=stdin_text, capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError(f"cli {' '.join(args)} failed: {done.stderr.strip()}")
    return done.stdout


failures = 0
with tempfile.TemporaryDirectory() as work:
    for r in range(rounds):
        size = rng.choice([16, 20, 24, 28, 32])
        secret = rng.randbytes(size)
        group_threshold, groups = structure()
        passphrase = "".join(chr(rng.randint(32, 126)) for _ in range(rng.randint(0, 12)))
        extendable = rng.random() < 0.7
        exponent = rng.choice([0, 0, 1, 1, 2])
        passphrase_file = None
        if passphrase:
            passphrase_file = os.path.join(work, "pw")
            with open(passphrase_file, "w", encoding="ascii") as f:
                f.write(passphrase)
        spec = [f"{t}of{n}" for t, n in groups]
        label = (
            f"round {r}: {size * 8} bits, {group_threshold} of {' '.join(spec)}, "
            f"ext={int(extendable)}, e={exponent}, passphrase of {len(passphrase)}"
        )

        # This crate splits, the reference combines.
        args = ["split", str(group_threshold)] + spec + ["--exponent", str(exponent)]
        if not extendable:
            args.append("--no-ext")
        lines = [l for l in run_cli(args, secret.hex() + "\n", passphrase_file).split("\n") if l]
        mnemonics, k = [], 0
        for _, count in groups:
            mnemonics.append(lines[k : k + count])
            k += count
        try:
            got = combine_mnemonics(selection(group_threshold, groups, mnemonics), passphrase.encode())
        except Exception as e:  # the reference raises on anything it rejects
            got = f"error: {e}"
        if got != secret:
            failures += 1
            print(f"FAIL crate -> reference, {label}: {got!r}")

        # The reference splits, this crate combines.
        mnemonics = generate_mnemonics(
            group_threshold, groups, secret, passphrase.encode(), extendable, exponent
        )
        chosen = selection(group_threshold, groups, mnemonics)
        try:
            got = run_cli(["combine"], "\n".join(chosen) + "\n", passphrase_file).strip()
        except RuntimeError as e:
            got = str(e)
        if got != secret.hex():
            failures += 1
            print(f"FAIL reference -> crate, {label}: {got}")

print(f"random rounds: {rounds - failures} passed, {failures} failed (seed {seed})")
sys.exit(1 if failures else 0)
