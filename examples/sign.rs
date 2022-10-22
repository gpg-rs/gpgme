use gpgme;
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
    #[structopt(long)]
    #[structopt(long, conflicts_with = "normal")]
    /// Create a detached signature
    detach: bool,
    #[structopt(long, conflicts_with = "normal", conflicts_with = "detach")]
    /// Create a clear text signature
    clear: bool,
    #[structopt(long)]
    /// Key to use for signing. Default key is used otherwise
    key: Option<String>,
    #[structopt(parse(from_os_str))]
    /// File to sign
    filename: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::from_args();
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
            .map_err(|e| format!("unable to find signing key: {:?}", e))?;
        ctx.add_signer(&key)
            .map_err(|e| format!("add_signer() failed: {:?}", e))?;
    }

    let filename = &args.filename;
    let mut input = File::open(filename)
        .map_err(|e| format!("can't open file `{}': {:?}", filename.display(), e))?;
    let mut output = Vec::new();
    let result = ctx
        .sign(mode, &mut input, &mut output)
        .map_err(|e| format!("signing failed {:?}", e))?;
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
