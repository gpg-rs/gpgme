extern crate getopts;
extern crate gpgme;

use std::env;
use std::fs::File;
use std::process::exit;

use getopts::Options;

use gpgme::{Context, Protocol};

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} [options] [SIGFILE] FILE", program);
    eprintln!("{}", opts.usage(&brief));
}

fn print_summary(summary: gpgme::SignatureSummary) {
    if summary.contains(gpgme::SIGNATURE_VALID) {
        print!(" valid");
    }
    if summary.contains(gpgme::SIGNATURE_GREEN) {
        print!(" green");
    }
    if summary.contains(gpgme::SIGNATURE_RED) {
        print!(" red");
    }
    if summary.contains(gpgme::SIGNATURE_KEY_REVOKED) {
        print!(" revoked");
    }
    if summary.contains(gpgme::SIGNATURE_KEY_EXPIRED) {
        print!(" key-expired");
    }
    if summary.contains(gpgme::SIGNATURE_SIG_EXPIRED) {
        print!(" sig-expired");
    }
    if summary.contains(gpgme::SIGNATURE_KEY_MISSING) {
        print!(" key-missing");
    }
    if summary.contains(gpgme::SIGNATURE_CRL_MISSING) {
        print!(" crl-missing");
    }
    if summary.contains(gpgme::SIGNATURE_CRL_TOO_OLD) {
        print!(" crl-too-old");
    }
    if summary.contains(gpgme::SIGNATURE_BAD_POLICY) {
        print!(" bad-policy");
    }
    if summary.contains(gpgme::SIGNATURE_SYS_ERROR) {
        print!(" sys-error");
    }
}

fn print_result(result: &gpgme::VerificationResult) {
    println!(
        "Original file name: {}",
        result.filename().unwrap_or("[none]")
    );
    for (i, sig) in result.signatures().enumerate() {
        println!("Signature {}", i);
        println!("  status ....: {:?}", sig.status());
        print!("  summary ...:");
        print_summary(sig.summary());
        println!("");
        println!("  fingerprint: {}", sig.fingerprint().unwrap_or("[none]"));
        println!("  created ...: {:?}", sig.creation_time());
        println!("  expires ...: {:?}", sig.expiration_time());
        println!("  validity ..: {:?}", sig.validity());
        println!("  val.reason : {:?}", sig.nonvalidity_reason());
        println!("  pubkey algo: {}", sig.key_algorithm());
        println!("  digest algo: {}", sig.hash_algorithm());
        println!("  pka address: {}", sig.pka_address().unwrap_or("[none]"));
        println!("  pka trust .: {:?}", sig.pka_trust());
        println!(
            "  other flags: {}{}",
            if sig.is_wrong_key_usage() {
                " wrong-key-usage"
            } else {
                ""
            },
            if sig.verified_by_chain() {
                " chain-model"
            } else {
                ""
            }
        );
    }
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let program = &args[0];

    let mut opts = Options::new();
    opts.optflag("h", "help", "display this help message");
    opts.optflag("", "openpgp", "use the OpenPGP protocol (default)");
    opts.optflag("", "cms", "use the CMS protocol");

    let matches = match opts.parse(&args[1..]) {
        Ok(matches) => matches,
        Err(fail) => {
            print_usage(program, &opts);
            eprintln!("{}", fail);
            exit(1);
        }
    };

    if matches.opt_present("h") {
        print_usage(program, &opts);
        return;
    }

    if matches.free.len() < 1 {
        print_usage(program, &opts);
        exit(1);
    }

    let proto = if matches.opt_present("cms") {
        Protocol::Cms
    } else {
        Protocol::OpenPgp
    };

    let mut ctx = Context::from_protocol(proto).unwrap();

    let signature = match File::open(&matches.free[0]) {
        Ok(file) => file,
        Err(err) => {
            eprintln!(
                "{}: can't open '{}': {}",
                program,
                &matches.free[0],
                err
            );
            exit(1);
        }
    };

    let result = if matches.free.len() > 1 {
        let signed = match File::open(&matches.free[1]) {
            Ok(file) => file,
            Err(err) => {
                eprintln!(
                    "{}: can't open '{}': {}",
                    program,
                    &matches.free[1],
                    err
                );
                exit(1);
            }
        };
        ctx.verify_detached(signature, signed)
    } else {
        ctx.verify_opaque(signature, &mut Vec::new())
    };

    match result {
        Ok(result) => print_result(&result),
        Err(err) => {
            eprintln!("{}: verification failed: {}", program, err);
            exit(1);
        }
    }
}
