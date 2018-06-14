extern crate gpgme;
#[macro_use]
extern crate quicli;

use std::fs::File;
use std::path::PathBuf;

use gpgme::data;
use gpgme::{Context, Data, ImportFlags};
use quicli::prelude::*;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(long = "url")]
    /// Import from given URLs
    url: bool,
    #[structopt(short = "0")]
    /// URLS are delimited by a null
    nul: bool,
    #[structopt(raw(required = "true"), parse(from_os_str))]
    filenames: Vec<PathBuf>,
}

main!(|args: Cli| {
    let mode = if args.url {
        if args.nul {
            Some(data::Encoding::Url0)
        } else {
            Some(data::Encoding::Url)
        }
    } else {
        None
    };

    let mut ctx = Context::from_protocol(gpgme::Protocol::OpenPgp)?;
    for file in args.filenames {
        println!("reading file `{}'", &file.display());

        let mut input = File::open(file)?;
        let mut data = Data::from_seekable_stream(input)?;
        mode.map(|m| data.set_encoding(m));
        print_import_result(ctx.import(&mut data).context("import failed")?);
    }
});

fn print_import_result(result: gpgme::ImportResult) {
    for import in result.imports() {
        print!(
            "  fpr: {} err: {:?} status:",
            import.fingerprint().unwrap_or("[none]"),
            import.result().err()
        );
        let status = import.status();
        if status.contains(ImportFlags::NEW) {
            print!(" new");
        }
        if status.contains(ImportFlags::UID) {
            print!(" uid");
        }
        if status.contains(ImportFlags::SIG) {
            print!(" sig");
        }
        if status.contains(ImportFlags::SUBKEY) {
            print!(" subkey");
        }
        if status.contains(ImportFlags::SECRET) {
            print!(" secret");
        }
        println!("");
    }
    println!("key import summary:");
    println!("        considered: {}", result.considered());
    println!("        no user id: {}", result.without_user_id());
    println!("          imported: {}", result.imported());
    println!("      imported rsa: {}", result.imported_rsa());
    println!("         unchanged: {}", result.unchanged());
    println!("      new user ids: {}", result.new_user_ids());
    println!("       new subkeys: {}", result.new_subkeys());
    println!("    new signatures: {}", result.new_signatures());
    println!("   new revocations: {}", result.new_revocations());
    println!("       secret read: {}", result.secret_considered());
    println!("   secret imported: {}", result.secret_imported());
    println!("  secret unchanged: {}", result.secret_unchanged());
    println!("      not imported: {}", result.not_imported());
}
