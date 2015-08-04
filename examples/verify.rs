#![allow(unused_must_use)]
extern crate getopts;
extern crate gpgme;

use std::env;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::process::exit;

use getopts::Options;

use gpgme::Data;
use gpgme::ops;

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} [options] [SIGFILE] FILE", program);
    write!(io::stderr(), "{}", opts.usage(&brief));
}

fn print_summary(summary: ops::SignatureSummary) {
    if summary.contains(ops::SIGNATURE_VALID) {
        print!(" valid");
    }
    if summary.contains(ops::SIGNATURE_GREEN) {
        print!(" green");
    }
    if summary.contains(ops::SIGNATURE_RED) {
        print!(" red");
    }
    if summary.contains(ops::SIGNATURE_KEY_REVOKED) {
        print!(" revoked");
    }
    if summary.contains(ops::SIGNATURE_KEY_EXPIRED) {
        print!(" key-expired");
    }
    if summary.contains(ops::SIGNATURE_SIG_EXPIRED) {
        print!(" sig-expired");
    }
    if summary.contains(ops::SIGNATURE_KEY_MISSING) {
        print!(" key-missing");
    }
    if summary.contains(ops::SIGNATURE_CRL_MISSING) {
        print!(" crl-missing");
    }
    if summary.contains(ops::SIGNATURE_CRL_TOO_OLD) {
        print!(" crl-too-old");
    }
    if summary.contains(ops::SIGNATURE_BAD_POLICY) {
        print!(" bad-policy");
    }
    if summary.contains(ops::SIGNATURE_SYS_ERROR) {
        print!(" sys-error");
    }
}

fn print_result(result: &ops::VerifyResult) {
    println!("Original file name: {}", result.filename().unwrap_or("[none]"));
    for (i, sig) in result.signatures().enumerate() {
        println!("Signature {}", i);
        println!("  status ....: {:?}", sig.status());
        print!  ("  summary ...:");
        print_summary(sig.summary());
        println!("");
        println!("  fingerprint: {}", sig.fingerprint().unwrap_or("[none]"));
        println!("  created ...: {}", sig.timestamp());
        println!("  expires ...: {}", sig.expires().unwrap_or(0));
        println!("  validity ..: {:?}", sig.validity());
        println!("  val.reason : {:?}", sig.validity_reason());
        println!("  pubkey algo: {}", sig.key_algorithm());
        println!("  digest algo: {}", sig.hash_algorithm());
        println!("  pka address: {}", sig.pka_address().unwrap_or("[none]"));
        println!("  pka trust .: {:?}", sig.pka_trust());
        println!("  other flags: {}{}",
                 if sig.wrong_key_usage() { " wrong-key-usage" } else { "" },
                 if sig.chain_model() { " chain-model" } else { "" });
    }
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "display this help message");
    opts.optflag("", "openpgp", "use the OpenPGP protocol (default)");
    opts.optflag("", "cms", "use the CMS protocol");

    let matches = match opts.parse(&args[1..]) {
        Ok(matches) => matches,
        Err(fail) => {
            print_usage(&program, &opts);
            writeln!(io::stderr(), "{}", fail);
            exit(1);
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, &opts);
        return;
    }

    if matches.free.len() < 1 {
        print_usage(&program, &opts);
        exit(1);
    }

    let proto = if matches.opt_present("cms") {
        gpgme::PROTOCOL_CMS
    } else {
        gpgme::PROTOCOL_OPENPGP
    };

    let mut ctx = gpgme::create_context().unwrap();
    ctx.set_protocol(proto).unwrap();

    let mut signature = {
        let file = match File::open(&matches.free[0]) {
            Ok(file) => file,
            Err(err) => {
                writeln!(io::stderr(), "{}: can't open '{}': {}",
                         &program, &matches.free[0], err);
                exit(1);
            }
        };
        match Data::from_seekable_reader(file) {
            Ok(data) => data,
            Err(..) => {
                writeln!(io::stderr(),
                         "{}: error allocating data object",
                         &program);
                exit(1);
            }
        }
    };

    let mut signed = if matches.free.len() > 1 {
        let file = match File::open(&matches.free[1]) {
            Ok(file) => file,
            Err(err) => {
                writeln!(io::stderr(), "{}: can't open '{}': {}",
                         &program, &matches.free[1], err);
                exit(1);
            }
        };
        match Data::from_seekable_reader(file) {
            Ok(data) => Some(data),
            Err(..) => {
                writeln!(io::stderr(),
                         "{}: error allocating data object",
                         &program);
                exit(1);
            }
        }
    } else {
        None
    };

    let mut plain = if signed.is_none() {
        Some(Data::new().unwrap())
    } else {
        None
    };

    match ctx.verify(&mut signature, signed.as_mut(), plain.as_mut()) {
        Ok(result) => print_result(&result),
        Err(err) => {
            writeln!(io::stderr(), "{}: verification failed: {}", &program, err);
            exit(1);
        },
    }
}
