extern crate tempdir;
extern crate gpgme;

use std::io;
use std::io::prelude::*;

use gpgme::Data;
use gpgme::keys;
use gpgme::ops;

use self::support::{setup, passphrase_cb};

#[macro_use]
mod support;

const KEYS: [&'static str; 2] = ["A0FF4590BB6122EDEF6E3C542D727CC768697734",
                                 "23FD347A419429BACCD5E72D6BC4778054ACD246"];

fn check_result(result: ops::SignResult, kind: ops::SignMode) {
    if let Some(signer) = result.invalid_signers().next() {
        panic!("Invalid signer found: {}", signer.fingerprint().unwrap_or("[no fingerprint]"));
    }
    assert_eq!(result.signatures().count(), 2);
    for signature in result.signatures() {
        assert_eq!(signature.kind(), kind);
        assert_eq!(signature.key_algorithm(), keys::PK_DSA);
        assert_eq!(signature.hash_algorithm(), keys::HASH_SHA1);
        assert!(KEYS.iter().any(|fpr| signature.fingerprint() == Some(fpr)));
    }
}

#[test]
fn test_signers() {
    let _gpghome = setup();
    let mut ctx = fail_if_err!(gpgme::create_context());
    fail_if_err!(ctx.set_protocol(gpgme::PROTOCOL_OPENPGP));
    let mut guard = ctx.with_passphrase_cb(passphrase_cb);

    guard.set_armor(true);
    guard.set_text_mode(true);

    guard.clear_signers();
    let keys: Vec<_> = guard.find_keys(KEYS.iter().cloned()).unwrap()
        .filter_map(Result::ok).collect();
    for key in &keys {
        guard.add_signer(key).unwrap();
    }

    assert_eq!(guard.signers().count(), keys.len());
    for key in guard.signers() {
        assert!(keys.iter().any(|k| k.fingerprint() == key.fingerprint()));
    }

    let mut input = fail_if_err!(Data::from_buffer(b"Hallo Leute\n"));
    let mut output = fail_if_err!(Data::new());
    check_result(fail_if_err!(guard.sign_normal(&mut input, &mut output)),
                 ops::SIGN_MODE_NORMAL);

    input.seek(io::SeekFrom::Start(0)).unwrap();
    output = fail_if_err!(Data::new());
    check_result(fail_if_err!(guard.sign_detached(&mut input, &mut output)),
                 ops::SIGN_MODE_DETACH);

    input.seek(io::SeekFrom::Start(0)).unwrap();
    output = fail_if_err!(Data::new());
    check_result(fail_if_err!(guard.sign_clear(&mut input, &mut output)),
                 ops::SIGN_MODE_CLEAR);
}
