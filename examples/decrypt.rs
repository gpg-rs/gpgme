extern crate gpgme;
#[macro_use]
extern crate quicli;

use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::PathBuf;

use gpgme::{Context, Protocol};
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
    /// File to decrypt
    filename: PathBuf,
}

main!(|args: Cli| {
    let proto = if args.cms {
        Protocol::Cms
    } else {
        Protocol::OpenPgp
    };

    let mut ctx = Context::from_protocol(proto)?;
    let mut input = File::open(&args.filename)?;
    let mut output = Vec::new();
    ctx.decrypt(&mut input, &mut output)
        .context("decrypting failed")?;

    println!("Begin Output:");
    io::stdout().write_all(&output)?;
    println!("End Output.");
});
