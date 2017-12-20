extern crate gpgme;
#[macro_use]
extern crate lazy_static;
extern crate tempdir;

use self::support::passphrase_cb;

#[macro_use]
mod support;

test_case! {
    test_symmetric_encrypt_decrypt(test) {
        let mut ciphertext = Vec::new();
        test.create_context().with_passphrase_provider(passphrase_cb, |ctx| {
            ctx.set_armor(true);
            ctx.set_text_mode(true);

            fail_if_err!(ctx.encrypt_symmetric("Hello World", &mut ciphertext));
        });
        assert!(ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----"));

        let mut plaintext = Vec::new();
        test.create_context().with_passphrase_provider(passphrase_cb, |ctx| {
            fail_if_err!(ctx.decrypt(&ciphertext, &mut plaintext));
        });
        assert_eq!(plaintext, b"Hello World");
    },
}
