extern crate getopts;
#[macro_use]
extern crate gpgme;

use std::env;
use std::process::exit;

use getopts::Options;

use gpgme::{Context, Protocol};

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} [options] [name] [version]", program);
    eprintln!("{}", opts.usage(&brief));
}

fn main() {
    require_gpgme_ver! {
        (1, 8) => {
            let args: Vec<_> = env::args().collect();
            let program = &args[0];

            let mut opts = Options::new();
            opts.optflag("h", "help", "display this help message");

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

            let mut ctx = Context::from_protocol(Protocol::GpgConf).unwrap();
            let result = ctx.query_swdb(matches.free.get(0), matches.free.get(1))
                .expect("query failed");
            println!("{:#?}", result);
        } else {
            eprintln!("This example requires GPGme version 1.8");
        }
    }
}
