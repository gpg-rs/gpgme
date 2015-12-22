extern crate tempdir;
extern crate gpgme;

use gpgme::{Data, StrError};
use gpgme::error::ErrorCode;
use gpgme::ops;

use self::support::{setup, passphrase_cb, check_data};

#[macro_use]
mod support;

const CIPHER_2: &'static [u8] = include_bytes!("./data/cipher-2.asc");

fn check_result(result: ops::VerifyResult, fpr: &str, summary: ops::SignatureSummary,
                status: ErrorCode) {
    assert_eq!(result.signatures().count(), 1);

    let signature = result.signatures().next().unwrap();
    assert_eq!(signature.summary(), summary);
    assert_eq!(signature.fingerprint(), Ok(fpr));
    assert_eq!(signature.status().err().map_or(0, |e| e.code()), status);
    assert_eq!(signature.notations().count(), 0);
    assert!(!signature.wrong_key_usage());
    assert_eq!(signature.validity(), gpgme::VALIDITY_UNKNOWN);
    assert_eq!(signature.validity_reason(), None);
}

#[test]
fn test_decrypt_verify() {
    let _gpghome = setup();
    let mut ctx = fail_if_err!(gpgme::create_context());
    fail_if_err!(ctx.set_protocol(gpgme::PROTOCOL_OPENPGP));
    ctx.with_passphrase_handler(passphrase_cb, |mut ctx| {
        let mut input = fail_if_err!(Data::from_buffer(CIPHER_2));
        let mut output = fail_if_err!(Data::new());

        let result = fail_if_err!(ctx.decrypt_and_verify(&mut input, &mut output));
        match result.0.unsupported_algorithm() {
            Ok(ref alg) => panic!("unsupported algorithm: {}", alg),
            Err(StrError::NotUtf8(ref alg, _)) => panic!("unsupported algorithm: {:?}", alg),
            _ => {},
        }
        check_result(result.1, "A0FF4590BB6122EDEF6E3C542D727CC768697734",
                     ops::SignatureSummary::empty(), 0);
        check_data(&mut output, b"Wenn Sie dies lesen k\xf6nnen, ist es wohl nicht\n\
                   geheim genug.\n");
    });
}
