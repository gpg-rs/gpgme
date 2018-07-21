extern crate gpgme;
#[macro_use]
extern crate quicli;

use std::fs::File;
use std::path::PathBuf;

use gpgme::{Context, Protocol, SignatureSummary};
use quicli::prelude::*;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(long = "openpgp")]
    /// Use the OpenPGP protocol
    openpgp: bool,
    #[structopt(long = "cms", conflicts_with = "openpgp")]
    /// Use the CMS protocol
    cms: bool,
    #[structopt(parse(from_os_str))]
    sigfile: PathBuf,
    #[structopt(parse(from_os_str))]
    filename: Option<PathBuf>,
}

main!(|args: Cli| {
    let proto = if args.cms {
        Protocol::Cms
    } else {
        Protocol::OpenPgp
    };

    let mut ctx = Context::from_protocol(proto)?;
    let sigfile = &args.sigfile;
    let signature =
        File::open(sigfile).with_context(|_| format!("can't open '{}'", sigfile.display()))?;
    let result = (if let Some(filename) = args.filename.as_ref() {
        let signed =
            File::open(filename).with_context(|_| format!("can't open '{}'", filename.display()))?;
        ctx.verify_detached(signature, signed)
    } else {
        ctx.verify_opaque(signature, &mut Vec::new())
    }).context("verification failed")?;

    print_result(&result);
});

fn print_summary(summary: SignatureSummary) {
    if summary.contains(SignatureSummary::VALID) {
        print!(" valid");
    }
    if summary.contains(SignatureSummary::GREEN) {
        print!(" green");
    }
    if summary.contains(SignatureSummary::RED) {
        print!(" red");
    }
    if summary.contains(SignatureSummary::KEY_REVOKED) {
        print!(" revoked");
    }
    if summary.contains(SignatureSummary::KEY_EXPIRED) {
        print!(" key-expired");
    }
    if summary.contains(SignatureSummary::SIG_EXPIRED) {
        print!(" sig-expired");
    }
    if summary.contains(SignatureSummary::KEY_MISSING) {
        print!(" key-missing");
    }
    if summary.contains(SignatureSummary::CRL_MISSING) {
        print!(" crl-missing");
    }
    if summary.contains(SignatureSummary::CRL_TOO_OLD) {
        print!(" crl-too-old");
    }
    if summary.contains(SignatureSummary::BAD_POLICY) {
        print!(" bad-policy");
    }
    if summary.contains(SignatureSummary::SYS_ERROR) {
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
