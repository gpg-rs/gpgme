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
    #[arg(long)]
    /// Create a detached signature
    detach: bool,
    #[arg(long, conflicts_with = "detach")]
    /// Create a clear text signature
    clear: bool,
    #[arg(long)]
    /// Key to use for signing. Default key is used otherwise
    key: Option<String>,
    /// File to sign
    filename: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    let proto = if args.cms {
        Protocol::Cms
    } else {
        Protocol::OpenPgp
    };

    let mode = if args.detach {
        gpgme::SignMode::Detached
    } else if args.clear {
        gpgme::SignMode::Clear
    } else {
        gpgme::SignMode::Normal
    };

    let mut ctx = Context::from_protocol(proto)?;
    ctx.set_armor(true);

    if let Some(key) = args.key {
        let key = ctx
            .get_secret_key(key)
            .map_err(|e| format!("unable to find signing key: {e:?}"))?;
        ctx.add_signer(&key)
            .map_err(|e| format!("add_signer() failed: {e:?}"))?;
    }

    let filename = &args.filename;
    let mut input = File::open(filename)
        .map_err(|e| format!("can't open file `{}': {e:?}", filename.display()))?;
    let mut output = Vec::new();
    let result = ctx
        .sign(mode, &mut input, &mut output)
        .map_err(|e| format!("signing failed {e:?}"))?;
    print_result(&result);

    println!("Begin Output:");
    io::stdout().write_all(&output)?;
    println!("End Output.");
    Ok(())
}

fn print_result(result: &gpgme::SigningResult) {
    for sig in result.new_signatures() {
        println!("Key fingerprint: {}", sig.fingerprint().unwrap_or("[none]"));
        println!("Signature type : {:?}", sig.mode());
        println!("Public key algo: {}", sig.key_algorithm());
        println!("Hash algo .....: {}", sig.hash_algorithm());
        println!("Creation time .: {:?}", sig.creation_time());
    }
}
