extern crate getopts;
extern crate gpgme;

use std::env;
use std::process::exit;

use getopts::Options;

use gpgme::{Context, Protocol};

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} [options] key-id", program);
    eprintln!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let program = &args[0];

    let mut opts = Options::new();
    opts.optflag("h", "help", "display this help message");
    opts.optflag("", "openpgp", "use the OpenPGP protocol (default)");
    opts.optflag("", "uiserver", "use the UI server");
    opts.optflag("", "cms", "use the CMS protocol");
    opts.optopt("", "key", "use key NAME for signing. Default key is used otherwise.", "NAME");

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

    if matches.free.len() != 1 {
        print_usage(program, &opts);
        exit(1);
    }

    let proto = if matches.opt_present("cms") {
        Protocol::Cms
    } else if matches.opt_present("uiserver") {
        Protocol::UiServer
    } else {
        Protocol::OpenPgp
    };

    let mut ctx = Context::from_protocol(proto).unwrap();
    let key_to_sign = ctx.find_key(&matches.free[0]).expect("no key matched given key-id");

    if let Some(key) = matches.opt_str("key") {
        if proto != Protocol::UiServer {
            let key = ctx.find_secret_key(key).unwrap();
            ctx.add_signer(&key).expect("add_signer() failed");
        } else {
            eprintln!("ignoring --key in UI-server mode");
        }
    }

    let users = Vec::<&[u8]>::new();
    ctx.sign_key(&key_to_sign, &users, None)
        .expect("signing failed");

    println!("Signed key for {}", matches.free[0]);
}
