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
    #[structopt(
        long = "uiserver",
        conflicts_with = "openpgp",
        conflicts_with = "cms"
    )]
    /// Use to UI server
    uiserver: bool,
    #[structopt(long = "normal")]
    /// Create a normal signature (default)
    normal: bool,
    #[structopt(long = "detach", conflicts_with = "normal")]
    /// Create a detached signature
    detach: bool,
    #[structopt(
        long = "clear",
        conflicts_with = "normal",
        conflicts_with = "detach"
    )]
    /// Create a clear text signature
    clear: bool,
    #[structopt(long = "key")]
    /// Key to use for signing. Default key is used otherwise
    key: Option<String>,
    #[structopt(parse(from_os_str))]
    /// File to sign
    filename: PathBuf,
}

main!(|args: Cli| {
    let proto = if args.cms {
        Protocol::Cms
    } else if args.uiserver {
        Protocol::UiServer
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
        if proto != Protocol::UiServer {
            let key = ctx
                .get_secret_key(key)
                .context("unable to find signing key")?;
            ctx.add_signer(&key).context("add_signer() failed")?;
        } else {
            eprintln!("ignoring --key in UI-server mode");
        }
    }

    let filename = &args.filename;
    let mut input =
        File::open(filename).with_context(|_| format!("can't open file `{}'", filename.display()))?;
    let mut output = Vec::new();
    let result = ctx
        .sign(mode, &mut input, &mut output)
        .context("signing failed")?;
    print_result(&result);

    println!("Begin Output:");
    io::stdout().write_all(&output)?;
    println!("End Output.");
});

fn print_result(result: &gpgme::SigningResult) {
    for sig in result.new_signatures() {
        println!("Key fingerprint: {}", sig.fingerprint().unwrap_or("[none]"));
        println!("Signature type : {:?}", sig.mode());
        println!("Public key algo: {}", sig.key_algorithm());
        println!("Hash algo .....: {}", sig.hash_algorithm());
        println!("Creation time .: {:?}", sig.creation_time());
    }
}
