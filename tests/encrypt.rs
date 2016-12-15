#[macro_use]
extern crate lazy_static;
extern crate tempdir;
extern crate gpgme;

use gpgme::Data;

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
        {
            let mut input = fail_if_err!(Data::from_buffer(b"Hello World"));
            let mut output = fail_if_err!(Data::from_writer(&mut ciphertext));

            fail_if_err!(ctx.encrypt_with_flags(Some(&key),
            gpgme::ENCRYPT_ALWAYS_TRUST,
            &mut input,
            &mut output));
        }
        assert!(ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----"));
        drop(ctx);

        let mut plaintext = Vec::new();
        test.create_context().with_passphrase_provider(passphrase_cb, |mut ctx| {
            let mut input = fail_if_err!(Data::from_buffer(&ciphertext));
            let mut output = fail_if_err!(Data::from_writer(&mut plaintext));

            fail_if_err!(ctx.decrypt(&mut input, &mut output));
        });
        assert_eq!(plaintext, b"Hello World");
    },
    test_symmetric_encrypt_decrypt(test) {
        let mut ctx = test.create_context();

        ctx.set_armor(true);
        ctx.set_text_mode(true);

        let mut ciphertext = Vec::new();
        ctx.with_passphrase_provider(passphrase_cb, |mut ctx| {
            let mut input = fail_if_err!(Data::from_buffer(b"Hello World"));
            let mut output = fail_if_err!(Data::from_writer(&mut ciphertext));

            fail_if_err!(ctx.encrypt_symmetric(&mut input, &mut output));
        });
        assert!(ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----"));
        drop(ctx);

        let mut plaintext = Vec::new();
        test.create_context().with_passphrase_provider(passphrase_cb, |mut ctx| {
            let mut input = fail_if_err!(Data::from_buffer(&ciphertext));
            let mut output = fail_if_err!(Data::from_writer(&mut plaintext));

            fail_if_err!(ctx.decrypt(&mut input, &mut output));
        });
        assert_eq!(plaintext, b"Hello World");
    },
}
