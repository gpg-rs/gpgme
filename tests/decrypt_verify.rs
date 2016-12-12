extern crate tempdir;
extern crate gpgme;

use gpgme::{Context, Data};
use gpgme::error::ErrorCode;

use self::support::{check_data, passphrase_cb, setup};

#[macro_use]
mod support;

const CIPHER_2: &'static [u8] = include_bytes!("./data/cipher-2.asc");

fn check_result(result: gpgme::VerificationResult, fpr: &str, summary: gpgme::SignatureSummary,
    status: ErrorCode) {
    assert_eq!(result.signatures().count(), 1);

    let signature = result.signatures().next().unwrap();
    assert_eq!(signature.summary(), summary);
    assert_eq!(signature.fingerprint(), Ok(fpr));
    assert_eq!(signature.status().err().map_or(0, |e| e.code()), status);
    assert_eq!(signature.notations().count(), 0);
    assert!(!signature.is_wrong_key_usage());
    assert_eq!(signature.validity(), gpgme::Validity::Unknown);
    assert_eq!(signature.nonvalidity_reason(), None);
}

#[test]
fn test_decrypt_verify() {
    let _gpghome = setup();
    let mut ctx = fail_if_err!(Context::from_protocol(gpgme::Protocol::OpenPgp));
    ctx.with_passphrase_provider(passphrase_cb, |mut ctx| {
        let mut input = fail_if_err!(Data::from_buffer(CIPHER_2));
        let mut output = fail_if_err!(Data::new());

        let result = fail_if_err!(ctx.decrypt_and_verify(&mut input, &mut output));
        match result.0.unsupported_algorithm() {
            Ok(alg) => panic!("unsupported algorithm: {}", alg),
            Err(Some(_)) => panic!("unsupported algorithm"),
            _ => {}
        }
        check_result(result.1,
                     "A0FF4590BB6122EDEF6E3C542D727CC768697734",
                     gpgme::SignatureSummary::empty(),
                     0);
        check_data(&mut output,
                   b"Wenn Sie dies lesen k\xf6nnen, ist es wohl nicht\n\
                   geheim genug.\n");
    });
}
