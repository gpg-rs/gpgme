extern crate tempdir;
extern crate gpgme;

use gpgme::{Protocol, Data};
use gpgme::ops;

use self::support::setup;

mod support;

#[test]
fn test_encrypt() {
    let _gpghome = setup();
    let mut ctx = gpgme::create_context().unwrap();
    ctx.set_protocol(Protocol::OpenPgp).unwrap();

    let mut input = Data::from_bytes(b"Hallo Leute\n").unwrap();
    let mut output = Data::new().unwrap();

    let key1 = ctx.find_key("A0FF4590BB6122EDEF6E3C542D727CC768697734").unwrap();
    let key2 = ctx.find_key("D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2").unwrap();
    let result = ctx.encrypt(&[key1, key2], ops::ENCRYPT_ALWAYS_TRUST,
                             &mut input, &mut output).unwrap();
    if let Some(recp) = result.invalid_recipients().next() {
        panic!("Invalid recipient encountered: {:?}", recp.fingerprint());
    }
}
