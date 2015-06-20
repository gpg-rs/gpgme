extern crate tempdir;
extern crate gpgme;

use gpgme::{Protocol, Data};
use gpgme::ops;

use self::support::setup;

#[macro_use]
mod support;

#[test]
fn test_encrypt() {
    let _gpghome = setup();
    let mut ctx = fail_if_err!(gpgme::create_context());
    fail_if_err!(ctx.set_protocol(Protocol::OpenPgp));

    let mut input = fail_if_err!(Data::from_bytes(b"Hallo Leute\n"));
    let mut output = fail_if_err!(Data::new());

    let key1 = fail_if_err!(ctx.find_key("A0FF4590BB6122EDEF6E3C542D727CC768697734"));
    let key2 = fail_if_err!(ctx.find_key("D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2"));
    let result = fail_if_err!(ctx.encrypt(&[key1, key2], ops::ENCRYPT_ALWAYS_TRUST,
                             &mut input, &mut output));
    if let Some(recp) = result.invalid_recipients().next() {
        panic!("Invalid recipient encountered: {:?}", recp.fingerprint());
    }
}
