"""Randomized differential test of what is rejected, against Trezor's reference package.

  rejection_rounds.py <cli> <rounds> [seed]

The other randomized test exchanges well-formed shares. This one checks that the two
implementations draw the line between acceptable and unacceptable input in the same place.

Each round decodes a batch of single mnemonics with both: random words under a checksum that
is usually valid, so that the length, padding and header checks behind the checksum are
reached, a third of them then altered as text (case, spacing, stray bytes, near-miss words).
Both must reject the same ones and decode the rest to the same fields.

Each round also splits one secret twice and recovers from arbitrary selections of the shares:
too few, too many, repeated, or mixed with shares from the second split or from another set.
Both must refuse the same selections and recover the same secret from the rest.

Two differences are known and are kept out of the generated input: Python's `str.split` and
`str.lower` accept a few characters (the separators U+001C to U+001F, and the Kelvin sign as
a "k") that this crate, which reads words as ASCII, does not.

The seed is printed so that a failing run can be repeated.
"""

import random
import secrets
import subprocess
import sys

from shamir_mnemonic import rs1024, shamir
from shamir_mnemonic.share import Share
from shamir_mnemonic.utils import MnemonicError
from shamir_mnemonic.wordlist import WORDLIST

# Sized so that the default run adds seconds, not minutes: the CLI is a debug build, in which
# the word lookup that compares every list entry is slow.
DECODINGS_PER_ROUND = 20
SELECTIONS_PER_ROUND = 4

cli = sys.argv[1]
rounds = int(sys.argv[2])
seed = int(sys.argv[3]) if len(sys.argv) > 3 else secrets.randbits(32)
rng = random.Random(seed)
print(f"rejection rounds: seed={seed} rounds={rounds}")


def run_cli(command, stdin_text):
    """The CLI's output, or None if it rejected the input. It exits with 1 to reject; any
    other failure, such as a panic, is a failure of this test."""
    done = subprocess.run([cli, command], input=stdin_text.encode(), capture_output=True)
    if done.returncode == 1:
        return None
    if done.returncode != 0:
        raise RuntimeError(f"cli {command} exited with {done.returncode}: {done.stderr.decode()}")
    return done.stdout.decode()


def words_under_checksum():
    """Random words, steered past the earlier checks often enough to reach the later ones."""
    count = rng.choice([20, 33]) if rng.random() < 0.35 else rng.randint(17, 45)
    data = [rng.randrange(1024) for _ in range(count - 3)]
    padding = (10 * (count - 7)) % 16
    if padding <= 8 and rng.random() < 0.6:  # clear the padding bits
        data[4] &= (1 << (10 - padding)) - 1
    if rng.random() < 0.5:  # put the group threshold at or below the group count
        params = (data[2] << 10) | data[3]
        threshold, total = (params >> 12) & 15, (params >> 8) & 15
        if threshold > total:
            params = (params & ~(0xFF << 8)) | (total << 12) | (threshold << 8)
            data[2], data[3] = params >> 10, params & 1023
    extendable = (data[1] >> 4) & 1
    customization = b"shamir_extendable" if extendable else b"shamir"
    r = rng.random()
    if r < 0.08:  # the checksum of the other format
        customization = b"shamir" if extendable else b"shamir_extendable"
    checksum = rs1024.create_checksum(data, customization)
    if r > 0.92:  # one wrong bit
        checksum[rng.randrange(3)] ^= 1 << rng.randrange(10)
    return [WORDLIST[i] for i in data + checksum]


def as_text(words):
    """The words as a mnemonic, a third of the time with one alteration. Each alteration either
    leaves the meaning alone (case, spacing) or has to make both implementations reject it."""
    w = list(words)
    if rng.random() >= 1 / 3:
        return " ".join(w)
    k = rng.randrange(len(w))
    kind = rng.randrange(12)
    if kind == 0:
        return " ".join(w).upper()
    if kind == 1:
        return "  " + "   ".join(w) + " "
    if kind == 2:
        return "\t".join(w)
    if kind == 3:
        return " ".join(w)  # no-break spaces, which both treat as spaces
    if kind == 4:
        return ",".join(w)
    if kind == 5:
        w[k] = w[k].capitalize()
    elif kind == 6:
        w[k] = w[k][:4]  # the four letters that identify the word
    elif kind == 7:
        w[k] += "s"
    elif kind == 8:
        w[k] += "\0"
    elif kind == 9:
        w[k] = w[k].ljust(8, "\0")
    elif kind == 10:
        w[k] = "\0" + w[k]
    else:
        w[k] += "​"  # zero-width space, which neither treats as a space
    return " ".join(w)


def reference_decode(mnemonic):
    """The line `cli decode` prints for an accepted mnemonic, or None."""
    try:
        s = Share.from_mnemonic(mnemonic)
    except MnemonicError:
        return None
    fields = (s.identifier, int(s.extendable), s.iteration_exponent, s.group_index)
    fields += (s.group_threshold, s.group_count, s.index, s.member_threshold)
    return "ok " + " ".join(str(f) for f in fields) + " " + s.value.hex()


def structure():
    """A group threshold and (threshold, count) per group, within the specification's limits."""
    group_count = rng.randint(1, 5)
    group_threshold = rng.randint(1, group_count)
    groups = []
    for _ in range(group_count):
        count = rng.randint(1, 16) if rng.random() < 0.15 else rng.randint(1, 5)
        groups.append((1 if count == 1 else rng.randint(2, count), count))
    return group_threshold, groups


def selection(group_threshold, groups, first, second, strangers):
    """Shares from the first split: a quarter of the time exactly a threshold of everything,
    otherwise any number from any groups; then sometimes disturbed."""
    if rng.random() < 0.25:
        picked = []
        for g in rng.sample(range(len(groups)), group_threshold):
            picked += rng.sample(first[g], groups[g][0])
    else:
        picked = []
        for g in range(len(groups)):
            if rng.random() < 0.7:
                picked += rng.sample(first[g], rng.randint(0, groups[g][1]))
    if picked and rng.random() < 0.3:  # one share from the second split of the same secret
        k = rng.randrange(len(picked))
        g = next(i for i, members in enumerate(first) if picked[k] in members)
        same_member = second[g][first[g].index(picked[k])]
        picked[k] = same_member if rng.random() < 0.5 else rng.choice(second[g])
    if picked and rng.random() < 0.1:  # one share from a set with another identifier
        picked[rng.randrange(len(picked))] = rng.choice(strangers)
    if picked and rng.random() < 0.2:  # exact repeats
        picked += rng.choices(picked, k=rng.randint(1, 3))
    rng.shuffle(picked)
    return picked


def mnemonics(group_threshold, groups, encrypted):
    return [[s.mnemonic() for s in g] for g in shamir.split_ems(group_threshold, groups, encrypted)]


failures = 0
accepted = recovered = 0
for r in range(rounds):
    # Single mnemonics.
    batch = [as_text(words_under_checksum()) for _ in range(DECODINGS_PER_ROUND)]
    lines = run_cli("decode", "\n".join(batch) + "\n").split("\n")[:-1]
    if len(lines) != len(batch):
        raise RuntimeError(f"cli decode printed {len(lines)} lines for {len(batch)} mnemonics")
    for mnemonic, line in zip(batch, lines):
        want = reference_decode(mnemonic)
        got = line if line.startswith("ok ") else None
        accepted += want is not None
        if got != want:
            failures += 1
            print(f"FAIL decode, round {r}: {mnemonic!r}\n  reference: {want}\n  crate:     {line}")

    # Selections from share sets.
    group_threshold, groups = structure()
    secret = rng.randbytes(rng.choice([16, 20, 32]))
    extendable = rng.random() < 0.5
    identifier, other_identifier = rng.sample(range(1 << 15), 2)
    encrypted = shamir.EncryptedMasterSecret.from_master_secret(
        secret, b"", identifier, extendable, 0
    )
    first = mnemonics(group_threshold, groups, encrypted)
    second = mnemonics(group_threshold, groups, encrypted)
    stranger = shamir.EncryptedMasterSecret(other_identifier, extendable, 0, encrypted.ciphertext)
    strangers = [m for g in mnemonics(group_threshold, groups, stranger) for m in g]
    for _ in range(SELECTIONS_PER_ROUND):
        picked = selection(group_threshold, groups, first, second, strangers)
        try:
            want = shamir.combine_mnemonics(picked, b"").hex()
        except MnemonicError:
            want = None
        got = run_cli("combine", "".join(m + "\n" for m in picked))
        got = got.strip() if got is not None else None
        recovered += want is not None
        if got != want:
            failures += 1
            spec = " ".join(f"{t}of{n}" for t, n in groups)
            print(f"FAIL combine, round {r}: {group_threshold} of {spec}, {len(picked)} shares")
            print(f"  reference: {want}\n  crate:     {got}")
            for m in picked:
                print(f"  {m}")

print(
    f"rejection rounds: {rounds * DECODINGS_PER_ROUND} decodings ({accepted} accepted), "
    f"{rounds * SELECTIONS_PER_ROUND} selections ({recovered} recovered), "
    f"{failures} disagreements (seed {seed})"
)
sys.exit(1 if failures else 0)
