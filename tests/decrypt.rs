extern crate tempdir;
extern crate gpgme;

use gpgme::{Data, StrError};

use self::support::{setup, passphrase_cb, check_data};

#[macro_use]
mod support;

const CIPHER_1: &'static [u8] = include_bytes!("./data/cipher-1.asc");

#[test]
fn test_decrypt() {
    let _gpghome = setup();
    let mut ctx = fail_if_err!(gpgme::create_context());
    ctx.set_protocol(gpgme::PROTOCOL_OPENPGP).unwrap();
    ctx.with_passphrase_handler(passphrase_cb, |mut ctx| {
        let mut input = fail_if_err!(Data::from_buffer(CIPHER_1));
        let mut output = fail_if_err!(Data::new());
        match fail_if_err!(ctx.decrypt(&mut input,
                    &mut output)).unsupported_algorithm() {
            Ok(ref alg) => panic!("unsupported algorithm: {}", alg),
            Err(StrError::NotUtf8(ref alg, _)) => panic!("unsupported algorithm: {:?}", alg),
            _ => {},
        }
        check_data(&mut output, b"Wenn Sie dies lesen k\xf6nnen, ist es wohl nicht\n\
                geheim genug.\n");
    });
}
