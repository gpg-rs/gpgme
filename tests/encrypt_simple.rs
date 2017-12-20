extern crate gpgme;
#[macro_use]
extern crate lazy_static;
extern crate tempdir;

use self::support::passphrase_cb;

#[macro_use]
mod support;

test_case! {
    test_simple_encrypt_decrypt(test) {
        let mut ctx = test.create_context();

        let key = fail_if_err!(ctx.find_keys(Some("alfa@example.net"))).nth(0).unwrap().unwrap();

        ctx.set_armor(true);
        ctx.set_text_mode(true);

        let mut ciphertext = Vec::new();
        fail_if_err!(ctx.encrypt_with_flags(Some(&key), "Hello World", &mut ciphertext, gpgme::EncryptFlags::ALWAYS_TRUST));
        assert!(ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----"));
        drop(ctx);

        let mut plaintext = Vec::new();
        test.create_context().with_passphrase_provider(passphrase_cb, |ctx| {
            fail_if_err!(ctx.decrypt(&ciphertext, &mut plaintext));
        });
        assert_eq!(plaintext, b"Hello World");
    }
}
