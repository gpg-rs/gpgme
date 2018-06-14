#[macro_use]
extern crate gpgme;
#[macro_use]
extern crate quicli;

use gpgme::{Context, Protocol};
use quicli::prelude::*;

#[derive(Debug, StructOpt)]
struct Cli {
    name: Option<String>,
    version: Option<String>,
}

main!(|args: Cli| {
    require_gpgme_ver! {
        (1, 8) => {
            let mut ctx = Context::from_protocol(Protocol::GpgConf)?;
            let result = ctx.query_swdb(args.name, args.version)
                .context("query failed")?;
            println!("{:#?}", result);
        } else {
            bail!("This example requires GPGme version 1.8");
        }
    }
});
