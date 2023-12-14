use std::{
    error::Error,
    fs::File,
    io::{self, prelude::*},
    path::PathBuf,
};

use clap::Parser;
use gpgme::{Context, Protocol};

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long)]
    /// Use the CMS protocol
    cms: bool,
    /// File to decrypt
    filename: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    let proto = if args.cms {
        Protocol::Cms
    } else {
        Protocol::OpenPgp
    };

    let mut ctx = Context::from_protocol(proto)?;
    let mut input = File::open(&args.filename)?;
    let mut output = Vec::new();
    ctx.decrypt(&mut input, &mut output)
        .map_err(|e| format!("decrypting failed: {e:?}"))?;

    println!("Begin Output:");
    io::stdout().write_all(&output)?;
    println!("End Output.");
    Ok(())
}
