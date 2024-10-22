use sealed_test::prelude::*;

use self::common::passphrase_cb;

#[macro_use]
mod common;

#[sealed_test]
fn test_simple_encrypt_decrypt() {
    common::with_test_harness(|| {
        let mut ctx = common::create_context();

        let key = ctx
            .find_keys(Some("alfa@example.net"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap();

        ctx.set_armor(true);
        ctx.set_text_mode(true);

        let mut ciphertext = Vec::new();
        ctx.encrypt_with_flags(
            Some(&key),
            "Hello World",
            &mut ciphertext,
            gpgme::EncryptFlags::ALWAYS_TRUST,
        )
        .unwrap();
        assert!(ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----"));
        drop(ctx);

        let mut plaintext = Vec::new();
        common::create_context().with_passphrase_provider(passphrase_cb, |ctx| {
            ctx.decrypt(&ciphertext, &mut plaintext).unwrap();
        });
        assert_eq!(plaintext, b"Hello World");

        let mut plaintext = Vec::new();
        let mut ctx = common::create_context().set_passphrase_provider(passphrase_cb);
        ctx.decrypt(&ciphertext, &mut plaintext).unwrap();
        assert_eq!(plaintext, b"Hello World");
    })
}
