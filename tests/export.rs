extern crate tempdir;
extern crate gpgme;

use gpgme::{Context, Data};

use self::support::setup;

#[macro_use]
mod support;

#[test]
fn test_export() {
    let _gpghome = setup();
    let mut ctx = fail_if_err!(Context::from_protocol(gpgme::Protocol::OpenPgp));
    ctx.set_armor(true);

    let mut output = fail_if_err!(Data::new());
    fail_if_err!(ctx.export(["Alpha", "Bob"].iter().cloned(),
                            gpgme::ExportMode::empty(),
                            Some(&mut output)));

    output = fail_if_err!(Data::new());
    let key1 = fail_if_err!(ctx.find_key("0x68697734"));
    let key2 = fail_if_err!(ctx.find_key("0xA9E3B0B2"));
    fail_if_err!(ctx.export_keys(&[key1, key2], gpgme::ExportMode::empty(), Some(&mut output)))
}
