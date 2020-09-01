use self::common::passphrase_cb;

#[macro_use]
mod common;

test_case! {
    test_symmetric_encrypt_decrypt(test) {
        let mut ciphertext = Vec::new();
        test.create_context().with_passphrase_provider(passphrase_cb, |ctx| {
            ctx.set_armor(true);
            ctx.set_text_mode(true);

            ctx.encrypt_symmetric("Hello World", &mut ciphertext).unwrap();
        });
        assert!(ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----"));

        let mut plaintext = Vec::new();
        test.create_context().with_passphrase_provider(passphrase_cb, |ctx| {
            ctx.decrypt(&ciphertext, &mut plaintext).unwrap();
        });
        assert_eq!(plaintext, b"Hello World");

        let mut plaintext = Vec::new();
        let mut ctx = test.create_context().set_passphrase_provider(passphrase_cb);
        ctx.decrypt(&ciphertext, &mut plaintext).unwrap();
        assert_eq!(plaintext, b"Hello World");
    }
}
