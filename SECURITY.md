# Security

## Reporting

If you believe you have found a vulnerability in this crate, please report it privately rather
than in a public issue:

- through GitHub's private vulnerability reporting on this repository ("Report a vulnerability"
  under the Security tab), or
- by email to security@ironbirdlabs.com.

Include the crate version, what you observed, and how to reproduce it. Private reporting gives
the maintainers a chance to look into it before details are public.

## Scope

Reports about this crate's own behaviour are the most useful: shares that other SLIP-39
implementations cannot recover, a recovered secret that differs from the one shared, shares
accepted that should be rejected, a panic on untrusted input, or secret material handled
differently from what the documentation describes.

The SLIP-39 design itself is published by SatoshiLabs, and the behaviour of the operating
system, allocator or hardware the crate runs on is outside this crate.

## Versions

Fixes, when made, are released as new versions of the crate rather than as patches to earlier
versions.
