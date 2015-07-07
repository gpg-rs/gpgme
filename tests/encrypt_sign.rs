extern crate tempdir;
extern crate gpgme;

use gpgme::Data;
use gpgme::keys;
use gpgme::ops;

use self::support::{setup, passphrase_cb};

#[macro_use]
mod support;

fn check_result(result: ops::SignResult, kind: ops::SignMode) {
    if let Some(signer) = result.invalid_signers().next() {
        panic!("Invalid signer found: {}", signer.fingerprint().unwrap_or("[no fingerprint]"));
    }
    assert_eq!(result.signatures().count(), 1);
    let signature = result.signatures().next().unwrap();
    assert_eq!(signature.kind(), kind);
    assert_eq!(signature.key_algorithm(), keys::PK_DSA);
    if signature.hash_algorithm() != keys::HASH_SHA1 {
        assert_eq!(signature.hash_algorithm(), keys::HASH_RMD160);
    }
    assert_eq!(signature.class(), 0);
    assert_eq!(signature.fingerprint(), Some("A0FF4590BB6122EDEF6E3C542D727CC768697734"));
}

#[test]
fn test_encrypt_sign() {
    let _gpghome = setup();
    let mut ctx = fail_if_err!(gpgme::create_context());
    fail_if_err!(ctx.set_protocol(gpgme::PROTOCOL_OPENPGP));
    let mut guard = ctx.with_passphrase_cb(passphrase_cb);

    guard.set_armor(true);
    guard.set_text_mode(true);

    let mut input = fail_if_err!(Data::from_buffer(b"Hallo Leute\n"));
    let mut output = fail_if_err!(Data::new());
    let key1 = fail_if_err!(guard.find_key("A0FF4590BB6122EDEF6E3C542D727CC768697734"));
    let key2 = fail_if_err!(guard.find_key("D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2"));
    let result = fail_if_err!(guard.encrypt_and_sign(&[key1, key2], ops::ENCRYPT_ALWAYS_TRUST,
                                                     &mut input, &mut output));
    if let Some(recp) = result.0.invalid_recipients().next() {
        panic!("Invalid recipient encountered: {:?}", recp.fingerprint());
    }
    check_result(result.1, ops::SIGN_MODE_NORMAL);

    if gpgme::init().check_version("1.4.3") {
        input = fail_if_err!(Data::from_buffer(b"Hallo Leute\n"));
        output = fail_if_err!(Data::new());
        check_result(fail_if_err!(guard.encrypt_and_sign(None, ops::EncryptFlags::empty(),
                                                         &mut input, &mut output)).1,
        ops::SIGN_MODE_NORMAL);
    }
}
