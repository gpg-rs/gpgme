extern crate tempdir;
extern crate gpgme;

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
    if signature.hash_algorithm() != gpgme::HashAlgorithm::Sha1 {
        assert_eq!(signature.hash_algorithm(), gpgme::HashAlgorithm::RipeMd160);
    }
    assert_eq!(signature.signature_class(), 0);
    assert_eq!(signature.fingerprint(),
               Ok("A0FF4590BB6122EDEF6E3C542D727CC768697734"));
}

#[test]
fn test_encrypt_sign() {
    let _gpghome = setup();
    let mut ctx = fail_if_err!(Context::from_protocol(gpgme::Protocol::OpenPgp));
    ctx.with_passphrase_provider(passphrase_cb, |mut ctx| {
        ctx.set_armor(true);
        ctx.set_text_mode(true);

        let mut input = fail_if_err!(Data::from_buffer(b"Hallo Leute\n"));
        let mut output = fail_if_err!(Data::new());
        let key1 = fail_if_err!(ctx.find_key("A0FF4590BB6122EDEF6E3C542D727CC768697734"));
        let key2 = fail_if_err!(ctx.find_key("D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2"));
        let result = fail_if_err!(ctx.sign_and_encrypt_with_flags(&[key1, key2],
                                                                  gpgme::ENCRYPT_ALWAYS_TRUST,
                                                                  &mut input,
                                                                  &mut output));
        if let Some(recp) = result.0.invalid_recipients().next() {
            panic!("Invalid recipient encountered: {:?}", recp.fingerprint());
        }
        check_result(result.1, gpgme::SignMode::Normal);

        if gpgme::init().check_version("1.4.3") {
            input = fail_if_err!(Data::from_buffer(b"Hallo Leute\n"));
            output = fail_if_err!(Data::new());
            check_result(fail_if_err!(ctx.sign_and_encrypt(None, &mut input, &mut output)).1,
                         gpgme::SignMode::Normal);
        }
    });
}
