#![allow(unused_must_use)]
extern crate getopts;
extern crate gpgme;

use std::env;
use std::io;
use std::io::prelude::*;
use std::process::exit;

use getopts::{HasArg, Occur, Options};

use gpgme::Data;
use gpgme::ops;

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} [options] FILENAME", program);
    write!(io::stderr(), "{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let program = &args[0];

    let mut opts = Options::new();
    opts.optflag("h", "help", "display this help message");
    opts.optflag("", "openpgp", "use the OpenPGP protocol (default)");
    opts.optflag("", "cms", "use the CMS protocol");
    opts.opt("r", "recipient", "encrypt message for NAME", "NAME", HasArg::Yes, Occur::Multi);

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

    if matches.free.len() != 1 {
        print_usage(program, &opts);
        exit(1);
    }

    let proto = if matches.opt_present("cms") {
        gpgme::PROTOCOL_CMS
    } else {
        gpgme::PROTOCOL_OPENPGP
    };

    let mut ctx = gpgme::create_context().unwrap();
    ctx.set_protocol(proto).unwrap();
    ctx.set_armor(true);

    let recipients = matches.opt_strs("r");
    let keys = if !recipients.is_empty() {
        ctx.find_keys(recipients)
           .unwrap()
           .filter_map(Result::ok)
           .filter(|k| k.can_encrypt())
           .collect()
    } else {
        Vec::new()
    };

    let mut input = match Data::load(&matches.free[0]) {
        Ok(input) => input,
        Err(err) => {
            writeln!(io::stderr(),
                     "{}: error reading '{}': {}",
                     program,
                     &matches.free[0],
                     err);
            exit(1);
        }
    };

    let mut output = Data::new().unwrap();
    match ctx.encrypt(&keys, ops::EncryptFlags::empty(), &mut input, &mut output) {
        Ok(..) => (),
        Err(err) => {
            writeln!(io::stderr(), "{}: encrypting failed: {}", program, err);
            exit(1);
        }
    }

    println!("Begin Output:");
    output.seek(io::SeekFrom::Start(0));
    io::copy(&mut output, &mut io::stdout());
    println!("End Output.");
}
