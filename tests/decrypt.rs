extern crate tempdir;
extern crate gpgme;

use gpgme::{Protocol, Data};

use self::support::{setup, passphrase_cb};

mod support;

const CIPHER_1: &'static [u8] = include_bytes!("./data/cipher-1.asc");

#[test]
fn test_decrypt() {
    let _gpghome = setup();
    let mut ctx = gpgme::create_context().unwrap();
    ctx.set_protocol(Protocol::OpenPgp).unwrap();
    let mut guard = ctx.with_passphrase_cb(passphrase_cb);

    let mut input = Data::from_bytes(CIPHER_1).unwrap();
    let mut output = Data::new().unwrap();

    let result = guard.decrypt(&mut input, &mut output);
    if let Err(err) = result {
        panic!("error: {}", err);
    }
    match result.unwrap().unsupported_algorithm() {
        Some(alg) => panic!("unsupported algorithm: {}", alg),
        None => (),
    }
}
