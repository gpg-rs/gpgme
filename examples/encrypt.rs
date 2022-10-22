use structopt;

use gpgme::{Context, Protocol};
use std::{
    error::Error,
    fs::File,
    io::{self, prelude::*},
    path::PathBuf,
};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(long)]
    /// Use the CMS protocol
    cms: bool,
    #[structopt(short, long = "recipient")]
    /// For whom to encrypt the messages
    recipients: Vec<String>,
    #[structopt(parse(from_os_str))]
    /// Files to encrypt
    filename: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::from_args();
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
        .map_err(|e| format!("can't open file `{}': {:?}", filename.display(), e))?;
    let mut output = Vec::new();
    ctx.encrypt(&keys, &mut input, &mut output)
        .map_err(|e| format!("encrypting failed: {:?}", e))?;

    println!("Begin Output:");
    io::stdout().write_all(&output)?;
    println!("End Output.");
    Ok(())
}
