extern crate tempdir;
extern crate gpgme;

use std::io;
use std::io::prelude::*;

use gpgme::{Context, Data};

use self::support::{passphrase_cb, setup};

#[macro_use]
mod support;

fn check_result(result: gpgme::SigningResult, mode: gpgme::SignMode) {
    if let Some(signer) = result.invalid_signers().next() {
        panic!("Invalid signer found: {}",
               signer.fingerprint().unwrap_or("[no fingerprint]"));
    }
    assert_eq!(result.new_signatures().count(), 1);
    let signature = result.new_signatures().next().unwrap();
    assert_eq!(signature.mode(), mode);
    assert_eq!(signature.key_algorithm(), gpgme::KeyAlgorithm::Dsa);
    assert_eq!(signature.hash_algorithm(), gpgme::HashAlgorithm::Sha1);
    assert_eq!(signature.signature_class(), 1);
    assert_eq!(signature.fingerprint(),
               Ok("A0FF4590BB6122EDEF6E3C542D727CC768697734"));
}

#[test]
fn test_sign() {
    let _gpghome = setup();
    let mut ctx = fail_if_err!(Context::from_protocol(gpgme::Protocol::OpenPgp));
    ctx.with_passphrase_provider(passphrase_cb, |mut ctx| {
        ctx.set_armor(true);
        ctx.set_text_mode(true);

        let mut input = fail_if_err!(Data::from_buffer(b"Hallo Leute\n"));
        let mut output = fail_if_err!(Data::new());
        check_result(fail_if_err!(ctx.sign_normal(&mut input, &mut output)),
                     gpgme::SignMode::Normal);

        input.seek(io::SeekFrom::Start(0)).unwrap();
        output = fail_if_err!(Data::new());
        check_result(fail_if_err!(ctx.sign_detached(&mut input, &mut output)),
                     gpgme::SignMode::Detached);

        input.seek(io::SeekFrom::Start(0)).unwrap();
        output = fail_if_err!(Data::new());
        check_result(fail_if_err!(ctx.sign_clear(&mut input, &mut output)),
                     gpgme::SignMode::Clear);
    });
}
