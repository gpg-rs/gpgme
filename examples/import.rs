#![allow(unused_must_use)]
extern crate getopts;
extern crate gpgme;

use std::env;
use std::io;
use std::io::prelude::*;
use std::process::exit;

use getopts::Options;

use gpgme::{Context, Data};
use gpgme::data;

fn print_import_result(result: gpgme::ImportResult) {
    for import in result.imports() {
        print!("  fpr: {} err: {:?} status:",
               import.fingerprint().unwrap_or("[none]"),
               import.result().err());
        let status = import.status();
        if status.contains(gpgme::IMPORT_NEW) {
            print!(" new");
        }
        if status.contains(gpgme::IMPORT_UID) {
            print!(" uid");
        }
        if status.contains(gpgme::IMPORT_SIG) {
            print!(" sig");
        }
        if status.contains(gpgme::IMPORT_SUBKEY) {
            print!(" subkey");
        }
        if status.contains(gpgme::IMPORT_SECRET) {
            print!(" secret");
        }
        println!("");
    }
    println!("key import summary:");
    println!("        considered: {}", result.considered());
    println!("        no user id: {}", result.without_user_id());
    println!("          imported: {}", result.imported());
    println!("      imported rsa: {}", result.imported_rsa());
    println!("         unchanged: {}", result.unchanged());
    println!("      new user ids: {}", result.new_user_ids());
    println!("       new subkeys: {}", result.new_subkeys());
    println!("    new signatures: {}", result.new_signatures());
    println!("   new revocations: {}", result.new_revocations());
    println!("       secret read: {}", result.secret_considered());
    println!("   secret imported: {}", result.secret_imported());
    println!("  secret unchanged: {}", result.secret_unchanged());
    println!("      not imported: {}", result.not_imported());
}

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} [options] FILENAME+", program);
    write!(io::stderr(), "{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let program = &args[0];

    let mut opts = Options::new();
    opts.optflag("h", "help", "display this help message");
    opts.optflag("", "url", "import from given URLs");
    opts.optflag("0", "", "URLs are delimited by a nul");

    let matches = match opts.parse(&args[1..]) {
        Ok(matches) => matches,
        Err(fail) => {
            print_usage(program, &opts);
            writeln!(io::stderr(), "{}", fail);
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

    let mode = if matches.opt_present("url") {
        if matches.opt_present("0") {
            Some(data::Encoding::Url0)
        } else {
            Some(data::Encoding::Url)
        }
    } else {
        None
    };

    let mut ctx = Context::from_protocol(gpgme::Protocol::OpenPgp).unwrap();
    for file in matches.free {
        println!("reading file `{}'", &file);

        let mut data = Data::load(file).unwrap();
        mode.map(|m| data.set_encoding(m));
        print_import_result(ctx.import(&mut data).expect("import failed"));
    }
}
