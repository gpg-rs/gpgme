use structopt;

use gpgme::{Context, ExportMode, Protocol};
use std::{
    error::Error,
    io::{self, prelude::*},
};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(long = "extern")]
    /// Send keys to the keyserver
    external: bool,
    #[structopt(raw(required = "true"))]
    /// Keys to export
    users: Vec<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::from_args();
    let mode = if args.external {
        ExportMode::EXTERN
    } else {
        ExportMode::empty()
    };

    let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
    ctx.set_armor(true);

    let keys = {
        let mut key_iter = ctx.find_keys(args.users)?;
        let keys: Vec<_> = key_iter.by_ref().collect::<Result<_, _>>()?;
        for key in &keys {
            println!(
                "keyid: {}  (fpr: {})",
                key.id().unwrap_or("?"),
                key.fingerprint().unwrap_or("?")
            );
        }
        if key_iter.finish()?.is_truncated() {
            Err("key listing unexpectedly truncated")?;
        }
        keys
    };

    if mode.contains(ExportMode::EXTERN) {
        println!("sending keys to keyserver");
        ctx.export_keys_extern(&keys, mode)
            .map_err(|e| format!("export failed: {:?}", e))?;
    } else {
        let mut output = Vec::new();
        ctx.export_keys(&keys, mode, &mut output)
            .map_err(|e| format!("export failed: {:?}", e))?;

        println!("Begin Result:");
        io::stdout().write_all(&output)?;
        println!("End Result.");
    }
    Ok(())
}
