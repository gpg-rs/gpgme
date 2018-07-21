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
    #[structopt(short = "r", long = "recipient")]
    /// For whom to encrypt the messages
    recipients: Vec<String>,
    #[structopt(parse(from_os_str))]
    /// Files to encrypt
    filename: PathBuf,
}

main!(|args: Cli| {
    let proto = if args.cms {
        Protocol::Cms
    } else {
        Protocol::OpenPgp
    };

    let mut ctx = Context::from_protocol(proto)?;
    ctx.set_armor(true);

    let keys = if !args.recipients.is_empty() {
        ctx.find_keys(args.recipients)?
            .filter_map(|x| x.ok())
            .filter(|k| k.can_encrypt())
            .collect()
    } else {
        Vec::new()
    };

    let filename = &args.filename;
    let mut input = File::open(&args.filename)
        .with_context(|_| format!("can't open file `{}'", filename.display()))?;
    let mut output = Vec::new();
    ctx.encrypt(&keys, &mut input, &mut output)
        .context("encrypting failed")?;

    println!("Begin Output:");
    io::stdout().write_all(&output)?;
    println!("End Output.");
});
