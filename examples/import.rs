#![allow(unused_must_use)]
extern crate getopts;
extern crate gpgme;

use std::env;
use std::io;
use std::io::prelude::*;
use std::process::exit;

use getopts::Options;

use gpgme::{Protocol, DataEncoding, Data};
use gpgme::ops;

fn print_import_result(result: ops::ImportResult) {
    for import in result.imports() {
        print!("  fpr: {} err: {} status:",
               import.fingerprint().unwrap_or("[none]"),
               import.result());
        let status = import.status();
        if status.contains(ops::IMPORT_NEW) {
            print!(" new");
        }
        if status.contains(ops::IMPORT_UID) {
            print!(" uid");
        }
        if status.contains(ops::IMPORT_SIG) {
            print!(" sig");
        }
        if status.contains(ops::IMPORT_SUBKEY) {
            print!(" subkey");
        }
        if status.contains(ops::IMPORT_SECRET) {
            print!(" secret");
        }
        println!("");
    }
    println!("key import summary:");
    println!("        considered: {}", result.considered());
    println!("        no user id: {}", result.no_user_id());
    println!("          imported: {}", result.imported());
    println!("      imported rsa: {}", result.imported_rsa());
    println!("         unchanged: {}", result.unchanged());
    println!("      new user ids: {}", result.new_user_ids());
    println!("       new subkeys: {}", result.new_subkeys());
    println!("    new signatures: {}", result.new_signatures());
    println!("   new revocations: {}", result.new_revocations());
    println!("       secret read: {}", result.secret_read());
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
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "display this help message");
    opts.optflag("", "url", "import from given URLs");
    opts.optflag("0", "", "URLs are delimited by a nul");

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

    let mode = if matches.opt_present("url") {
        if matches.opt_present("0") {
            Some(DataEncoding::Url0)
        } else {
            Some(DataEncoding::Url)
        }
    } else {
        None
    };

    let mut ctx = gpgme::init().unwrap().create_context().unwrap();
    ctx.set_protocol(Protocol::OpenPgp).unwrap();

    for file in matches.free {
        println!("reading file `{}'", &file);

        let mut data = Data::load(&file).unwrap();
        mode.map(|m| data.set_encoding(m));
        print_import_result(ctx.import(&mut data).unwrap());
    }
}
