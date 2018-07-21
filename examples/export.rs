extern crate gpgme;
#[macro_use]
extern crate quicli;

use std::io;
use std::io::prelude::*;
use std::result::Result as StdResult;

use gpgme::{Context, ExportMode, Protocol};
use quicli::prelude::*;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(long = "extern")]
    /// Send keys to the keyserver
    external: bool,
    #[structopt(raw(required = "true"))]
    /// Keys to export
    users: Vec<String>,
}

main!(|args: Cli| {
    let mode = if args.external {
        ExportMode::EXTERN
    } else {
        ExportMode::empty()
    };

    let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
    ctx.set_armor(true);

    let keys = {
        let mut key_iter = ctx.find_keys(args.users)?;
        let keys: Vec<_> = key_iter.by_ref().collect::<StdResult<_, _>>()?;
        for key in &keys {
            println!(
                "keyid: {}  (fpr: {})",
                key.id().unwrap_or("?"),
                key.fingerprint().unwrap_or("?")
            );
        }
        if key_iter.finish()?.is_truncated() {
            bail!("key listing unexpectedly truncated");
        }
        keys
    };

    if mode.contains(ExportMode::EXTERN) {
        println!("sending keys to keyserver");
        ctx.export_keys_extern(&keys, mode)
            .context("export failed")?;
    } else {
        let mut output = Vec::new();
        ctx.export_keys(&keys, mode, &mut output)
            .context("export failed")?;

        println!("Begin Result:");
        io::stdout().write_all(&output)?;
        println!("End Result.");
    }
});
