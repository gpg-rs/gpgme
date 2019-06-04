use structopt;

use gpgme::{Context, KeyListMode, Protocol};
use std::error::Error;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(long = "openpgp")]
    /// Use the OpenPGP protocol
    openpgp: bool,
    #[structopt(long = "cms", conflicts_with = "openpgp")]
    /// Use the CMS protocol
    cms: bool,
    #[structopt(long = "local")]
    /// Use GPGME_KEYLIST_MODE_LOCAL
    local: bool,
    #[structopt(long = "extern")]
    /// Use GPGME_KEYLIST_MODE_EXTERN
    external: bool,
    #[structopt(long = "sigs")]
    /// Use GPGME_KEYLIST_MODE_SIGS
    sigs: bool,
    #[structopt(long = "sig-notations")]
    /// Use GPGME_KEYLIST_MODE_SIG_NOTATIONS
    notations: bool,
    #[structopt(long = "ephemeral")]
    /// Use GPGME_KEYLIST_MODE_EPHEMERAL
    ephemeral: bool,
    #[structopt(long = "validate")]
    /// Use GPGME_KEYLIST_MODE_VALIDATE
    validate: bool,
    users: Vec<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::from_args();
    let proto = if args.cms {
        Protocol::Cms
    } else {
        Protocol::OpenPgp
    };

    let mut mode = KeyListMode::empty();
    if args.local {
        mode.insert(KeyListMode::LOCAL);
    }
    if args.external {
        mode.insert(KeyListMode::EXTERN);
    }
    if args.sigs {
        mode.insert(KeyListMode::SIGS);
    }
    if args.notations {
        mode.insert(KeyListMode::SIG_NOTATIONS);
    }
    if args.ephemeral {
        mode.insert(KeyListMode::EPHEMERAL);
    }
    if args.validate {
        mode.insert(KeyListMode::VALIDATE);
    }

    let mut ctx = Context::from_protocol(proto)?;
    ctx.set_key_list_mode(mode)?;
    let mut keys = ctx.find_keys(args.users)?;
    for key in keys.by_ref().filter_map(|x| x.ok()) {
        println!("keyid   : {}", key.id().unwrap_or("?"));
        println!("fpr     : {}", key.fingerprint().unwrap_or("?"));
        println!(
            "caps    : {}{}{}{}",
            if key.can_encrypt() { "e" } else { "" },
            if key.can_sign() { "s" } else { "" },
            if key.can_certify() { "c" } else { "" },
            if key.can_authenticate() { "a" } else { "" }
        );
        println!(
            "flags   :{}{}{}{}{}{}",
            if key.has_secret() { " secret" } else { "" },
            if key.is_revoked() { " revoked" } else { "" },
            if key.is_expired() { " expired" } else { "" },
            if key.is_disabled() { " disabled" } else { "" },
            if key.is_invalid() { " invalid" } else { "" },
            if key.is_qualified() { " qualified" } else { "" }
        );
        for (i, user) in key.user_ids().enumerate() {
            println!("userid {}: {}", i, user.id().unwrap_or("[none]"));
            println!("valid  {}: {:?}", i, user.validity())
        }
        println!("");
    }

    if keys.finish()?.is_truncated() {
        Err("key listing unexpectedly truncated")?;
    }
    Ok(())
}
