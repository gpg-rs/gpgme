#![allow(unused_must_use)]
extern crate getopts;
extern crate gpgme;

use std::env;
use std::io;
use std::io::prelude::*;
use std::process::exit;

use getopts::Options;

use gpgme::Data;
use gpgme::ops;

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} [options] USERID+", program);
    write!(io::stderr(), "{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let program = &args[0];

    let mut opts = Options::new();
    opts.optflag("h", "help", "display this help message");
    opts.optflag("", "extern", "send keys to the keyserver");

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

    let mode = if matches.opt_present("extern") {
        ops::EXPORT_EXTERN
    } else {
        ops::ExportMode::empty()
    };

    let mut ctx = gpgme::create_context().unwrap();
    ctx.set_protocol(gpgme::PROTOCOL_OPENPGP).unwrap();
    ctx.set_armor(true);

    let keys = {
        let mut key_iter = ctx.find_keys(matches.free).unwrap();
        let keys: Vec<_> = key_iter.by_ref().collect::<Result<_, _>>().unwrap();
        for key in &keys {
            println!("keyid: {}  (fpr: {})",
                     key.id().unwrap_or("?"),
                     key.fingerprint().unwrap_or("?"));
        }
        if key_iter.finish().unwrap().truncated() {
            writeln!(io::stderr(),
                     "{}: key listing unexpectedly truncated",
                     program);
            exit(1);
        }
        keys
    };

    if mode.contains(ops::EXPORT_EXTERN) {
        println!("sending keys to keyserver");
        if let Err(err) = ctx.export_keys(&keys, mode, None) {
            writeln!(io::stderr(), "{}: export failed: {}", program, err);
            exit(1);
        }
    } else {
        let mut output = Data::new().unwrap();
        if let Err(err) = ctx.export_keys(&keys, mode, Some(&mut output)) {
            writeln!(io::stderr(), "{}: export failed: {}", program, err);
            exit(1);
        }

        println!("Begin Result:");
        output.seek(io::SeekFrom::Start(0));
        io::copy(&mut output, &mut io::stdout());
        println!("End Result.");
    }
}
