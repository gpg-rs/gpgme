use sealed_test::prelude::*;

use self::common::passphrase_cb;

#[macro_use]
mod common;

#[sealed_test]
fn test_symmetric_encrypt_decrypt() {
    common::with_test_harness(|| {
        let mut ciphertext = Vec::new();
        common::create_context().with_passphrase_provider(passphrase_cb, |ctx| {
            ctx.set_armor(true);
            ctx.set_text_mode(true);

            ctx.encrypt_symmetric("Hello World", &mut ciphertext)
                .unwrap();
        });
        assert!(ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----"));

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
