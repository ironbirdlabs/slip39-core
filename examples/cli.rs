//! Tiny CLI, mainly for interoperability checks against other implementations.
//!
//!   cli split <group-threshold> <t>of<n>... [--no-ext] [--passphrase-file PATH]
//!       reads the hex-encoded secret from stdin, prints one mnemonic per line
//!   cli combine [--passphrase-file PATH]
//!       reads one mnemonic per line from stdin, prints the hex-encoded secret
//!
//! Secrets and passphrases are not accepted on the command line, since arguments can be recorded
//! in shell history and are visible to other processes while the program runs.

use std::io::Read;
use std::process::exit;

use slip39_core::{GroupSpec, Zeroizing};

const USAGE: &str = "\
usage: cli split <group-threshold> <t>of<n>... [--no-ext] [--passphrase-file PATH]   (hex secret on stdin)
       cli combine [--passphrase-file PATH]                                      (mnemonics on stdin)";

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    exit(1)
}

fn read_stdin() -> Zeroizing<String> {
    let mut input = Zeroizing::new(String::new());
    std::io::stdin()
        .read_to_string(&mut input)
        .unwrap_or_else(|e| fail(&format!("cannot read stdin: {e}")));
    input
}

fn read_passphrase(path: Option<&str>) -> Zeroizing<Vec<u8>> {
    let Some(path) = path else {
        return Zeroizing::new(Vec::new());
    };
    let mut bytes = Zeroizing::new(
        std::fs::read(path)
            .unwrap_or_else(|e| fail(&format!("cannot read passphrase file {path}: {e}"))),
    );
    // Strip one trailing line ending, which editors add.
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    bytes
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut passphrase_file, mut extendable, mut positional) = (None, true, Vec::new());
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--passphrase-file" => {
                i += 1;
                passphrase_file = Some(
                    args.get(i)
                        .cloned()
                        .unwrap_or_else(|| fail("--passphrase-file needs a path")),
                );
            }
            "--no-ext" => extendable = false,
            other => positional.push(other.to_string()),
        }
        i += 1;
    }
    let passphrase = read_passphrase(passphrase_file.as_deref());

    match positional.first().map(String::as_str) {
        Some("split") if positional.len() >= 3 => {
            let group_threshold: u8 = positional[1]
                .parse()
                .unwrap_or_else(|_| fail("group threshold must be a number from 1 to 16"));
            let groups: Vec<GroupSpec> = positional[2..]
                .iter()
                .map(|g| {
                    g.split_once("of")
                        .and_then(|(t, n)| Some(GroupSpec::new(t.parse().ok()?, n.parse().ok()?)))
                        .unwrap_or_else(|| fail(&format!("group '{g}' must look like 3of5")))
                })
                .collect();
            let input = read_stdin();
            let hex_secret = input
                .split_whitespace()
                .next()
                .unwrap_or_else(|| fail("no secret on stdin; pipe in the hex-encoded secret"));
            let secret = Zeroizing::new(hex::decode(hex_secret).unwrap_or_else(|e| {
                match e {
                    hex::FromHexError::OddLength => eprintln!(
                        "error: the secret has {} hex digits, an odd count; every byte needs two digits",
                        hex_secret.len()
                    ),
                    hex::FromHexError::InvalidHexCharacter { c, index } => {
                        eprintln!("error: '{c}' at position {index} is not a hex digit");
                        eprintln!("hint: to shard text, encode it first:  printf 'my secret' | xxd -p");
                    }
                    other => eprintln!("error: {other}"),
                }
                eprintln!("note: the secret must be at least 16 bytes with an even count; 16 and 32 are the sizes the specification requires implementations to support");
                exit(1)
            }));
            let groups = slip39_core::generate_mnemonics(
                group_threshold,
                &groups,
                &secret,
                &passphrase,
                extendable,
                0,
            )
            .unwrap_or_else(|e| fail(&e.to_string()));
            for mnemonic in groups.iter().flatten() {
                println!("{mnemonic}");
            }
        }
        Some("combine") if positional.len() == 1 => {
            let input = read_stdin();
            let lines: Vec<&str> = input
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            match slip39_core::combine_mnemonics(&lines, &passphrase) {
                Ok(secret) => println!("{}", hex::encode(&*secret)),
                Err(e) => fail(&e.to_string()),
            }
        }
        _ => {
            eprintln!("{USAGE}");
            exit(2)
        }
    }
}
