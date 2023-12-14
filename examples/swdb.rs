extern crate gpgme;

use std::error::Error;

use clap::Parser;
use gpgme::{Context, Protocol};

#[derive(Debug, Parser)]
struct Cli {
    name: Option<String>,
    version: Option<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    let mut ctx = Context::from_protocol(Protocol::GpgConf)?;
    let result = ctx
        .query_swdb(args.name, args.version)
        .map_err(|e| format!("query failed: {e:?}"))?;
    println!("{result:#?}");
    Ok(())
}
