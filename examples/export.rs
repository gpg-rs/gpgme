extern crate getopts;
extern crate gpgme;

use std::env;
use std::io;
use std::io::prelude::*;
use std::process::exit;

use getopts::Options;

use gpgme::{Context, Protocol};

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} [options] USERID+", program);
    eprintln!("{}", opts.usage(&brief));
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

    let mode = if matches.opt_present("extern") {
        gpgme::EXPORT_EXTERN
    } else {
        gpgme::ExportMode::empty()
    };

    let mut ctx = Context::from_protocol(Protocol::OpenPgp).unwrap();
    ctx.set_armor(true);

    let keys = {
        let mut key_iter = ctx.find_keys(matches.free).unwrap();
        let keys: Vec<_> = key_iter.by_ref().collect::<Result<_, _>>().unwrap();
        for key in &keys {
            println!(
                "keyid: {}  (fpr: {})",
                key.id().unwrap_or("?"),
                key.fingerprint().unwrap_or("?")
            );
        }
        if key_iter.finish().unwrap().is_truncated() {
            panic!("key listing unexpectedly truncated");
        }
        keys
    };

    if mode.contains(gpgme::EXPORT_EXTERN) {
        println!("sending keys to keyserver");
        ctx.export_keys_extern(&keys, mode).expect("export failed");
    } else {
        let mut output = Vec::new();
        ctx.export_keys(&keys, mode, &mut output)
            .expect("export failed");

        println!("Begin Result:");
        io::stdout().write_all(&output).unwrap();
        println!("End Result.");
    }
}
