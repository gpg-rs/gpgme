#[macro_use]
extern crate gpgme;
#[macro_use]
extern crate quicli;

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
    #[structopt(long = "uiserver", conflicts_with = "openpgp", conflicts_with = "cms")]
    /// Use to UI server
    uiserver: bool,
    #[structopt(long = "key")]
    /// Key to use for signing. Default key is used otherwise
    key: Option<String>,
    /// Key to sign
    keyid: String,
}

main!(|args: Cli| {
    require_gpgme_ver! {
        (1, 7) => {
            let proto = if args.cms {
                Protocol::Cms
            } else if args.uiserver {
                Protocol::UiServer
            } else {
                Protocol::OpenPgp
            };

            let mut ctx = Context::from_protocol(proto)?;
            let key_to_sign = ctx.get_key(&args.keyid).context("no key matched given key-id")?;

            if let Some(key) = args.key {
                if proto != Protocol::UiServer {
                    let key = ctx.get_secret_key(key).context("unable to find signing key")?;
                    ctx.add_signer(&key).context("add_signer() failed")?;
                } else {
                    eprintln!("ignoring --key in UI-server mode");
                }
            }

            let users = Vec::<&[u8]>::new();
            ctx.sign_key(&key_to_sign, &users, None)
                .context("signing failed")?;

            println!("Signed key for {}", args.keyid);
        } else {
            bail!("This example requires GPGme version 1.7");
        }
    }
});
