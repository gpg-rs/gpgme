use std::error::Error;

use clap::Parser;
use gpgme::{Context, Protocol};

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long)]
    /// Use the CMS protocol
    cms: bool,
    #[arg(long)]
    /// Key to use for signing. Default key is used otherwise
    key: Option<String>,
    /// Key to sign
    keyid: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    let proto = if args.cms {
        Protocol::Cms
    } else {
        Protocol::OpenPgp
    };

    let mut ctx = Context::from_protocol(proto)?;
    let key_to_sign = ctx
        .get_key(&args.keyid)
        .map_err(|e| format!("no key matched given key-id: {e:?}"))?;

    if let Some(key) = args.key {
        let key = ctx
            .get_secret_key(key)
            .map_err(|e| format!("unable to find signing key: {e:?}"))?;
        ctx.add_signer(&key)
            .map_err(|e| format!("add_signer() failed: {e:?}"))?;
    }

    ctx.sign_key(&key_to_sign, None::<String>, Default::default())
        .map_err(|e| format!("signing failed: {e:?}"))?;

    println!("Signed key for {}", args.keyid);
    Ok(())
}
