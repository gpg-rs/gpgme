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
    let brief = format!("Usage: {} [options] FILENAME", program);
    write!(io::stderr(), "{}", opts.usage(&brief));
}

fn print_result(result: &ops::SignResult) {
    for sig in result.signatures() {
        println!("Key fingerprint: {}", sig.fingerprint().unwrap_or("[none]"));
        println!("Signature type : {:?}", sig.kind());
        println!("Public key algo: {}", sig.key_algorithm());
        println!("Hash algo .....: {}", sig.hash_algorithm());
        println!("Creation time .: {}", sig.timestamp());
    }
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let program = &args[0];

    let mut opts = Options::new();
    opts.optflag("h", "help", "display this help message");
    opts.optflag("", "openpgp", "use the OpenPGP protocol (default)");
    opts.optflag("", "cms", "use the CMS protocol");
    opts.optflag("", "uiserver", "use the UI server");
    opts.optflag("", "normal", "create a normal signature (default)");
    opts.optflag("", "detach", "create a detached signature");
    opts.optflag("", "clear", "create a clear text signature");
    opts.optopt("", "key", "use key NAME for signing", "NAME");

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
    } else if matches.opt_present("uiserver") {
        gpgme::PROTOCOL_UISERVER
    } else {
        gpgme::PROTOCOL_OPENPGP
    };

    let mode = if matches.opt_present("detach") {
        ops::SIGN_MODE_DETACH
    } else if matches.opt_present("clear") {
        ops::SIGN_MODE_CLEAR
    } else {
        ops::SIGN_MODE_NORMAL
    };

    let mut ctx = gpgme::create_context().unwrap();
    ctx.set_protocol(proto).unwrap();
    ctx.set_armor(true);

    match matches.opt_str("key") {
        Some(key) => {
            if proto != gpgme::PROTOCOL_UISERVER {
                let key = ctx.find_secret_key(key).unwrap();
                ctx.add_signer(&key).unwrap();
            } else {
                writeln!(io::stderr(),
                         "{}: ignoring --key in UI-server mode",
                         program);
            }
        }
        None => (),
    }

    let mut input = match Data::load(matches.free[0].clone()) {
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
    match ctx.sign(mode, &mut input, &mut output) {
        Ok(result) => print_result(&result),
        Err(err) => {
            writeln!(io::stderr(), "{}: signing failed: {}", program, err);
            exit(1);
        }
    }

    println!("Begin Output:");
    output.seek(io::SeekFrom::Start(0));
    io::copy(&mut output, &mut io::stdout());
    println!("End Output.");
}
