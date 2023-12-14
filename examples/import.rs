use std::{error::Error, fs::File, path::PathBuf};

use clap::Parser;
use gpgme::{data, Context, Data, ImportFlags};

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long)]
    /// Import from given URLs
    url: bool,
    #[arg(short = '0')]
    /// URLS are delimited by a null
    nul: bool,
    #[arg(num_args(1..))]
    filenames: Vec<PathBuf>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();
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
        println!("reading file `{}'", file.display());

        let input = File::open(file)?;
        let mut data = Data::from_seekable_stream(input)?;
        mode.map(|m| data.set_encoding(m));
        print_import_result(
            ctx.import(&mut data)
                .map_err(|e| format!("import failed {e:?}"))?,
        );
    }
    Ok(())
}

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
        println!();
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
