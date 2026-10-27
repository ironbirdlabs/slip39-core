"""Thin driver around Trezor's reference package, shamir-mnemonic, for the interop check.

  interop.py combine <passphrase>                                 mnemonics on stdin -> hex secret
  interop.py generate <hex> <gt> <passphrase> <ext 0|1> <exp> <t>of<n>...   -> one mnemonic per line
"""

import sys

from shamir_mnemonic import combine_mnemonics, generate_mnemonics

cmd = sys.argv[1]
if cmd == "combine":
    mnemonics = [line.strip() for line in sys.stdin if line.strip()]
    print(combine_mnemonics(mnemonics, sys.argv[2].encode()).hex())
elif cmd == "generate":
    secret = bytes.fromhex(sys.argv[2])
    group_threshold = int(sys.argv[3])
    passphrase = sys.argv[4].encode()
    extendable = sys.argv[5] == "1"
    exponent = int(sys.argv[6])
    groups = [tuple(int(x) for x in g.split("of")) for g in sys.argv[7:]]
    for group in generate_mnemonics(group_threshold, groups, secret, passphrase, extendable, exponent):
        for mnemonic in group:
            print(mnemonic)
else:
    sys.exit("unknown command")
