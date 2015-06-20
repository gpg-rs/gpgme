extern crate tempdir;
extern crate gpgme;

use gpgme::{Protocol, Data};

use self::support::{setup, passphrase_cb};

#[macro_use]
mod support;

const CIPHER_1: &'static [u8] = include_bytes!("./data/cipher-1.asc");

#[test]
fn test_decrypt() {
    let _gpghome = setup();
    let mut ctx = fail_if_err!(gpgme::create_context());
    ctx.set_protocol(Protocol::OpenPgp).unwrap();
    let mut guard = ctx.with_passphrase_cb(passphrase_cb);

    let mut input = fail_if_err!(Data::from_bytes(CIPHER_1));
    let mut output = fail_if_err!(Data::new());
    if let Some(alg) = fail_if_err!(guard.decrypt(&mut input,
                                                  &mut output)).unsupported_algorithm() {
        panic!("unsupported algorithm: {}", alg);
    }
}
