extern crate gpgme;
use structopt;

use gpgme::{Context, Protocol};
use std::error::Error;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Cli {
    name: Option<String>,
    version: Option<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::from_args();
    let mut ctx = Context::from_protocol(Protocol::GpgConf)?;
    let result = ctx
        .query_swdb(args.name, args.version)
        .map_err(|e| format!("query failed: {:?}", e))?;
    println!("{:#?}", result);
    Ok(())
}
