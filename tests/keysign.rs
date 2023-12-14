use gpgme::KeyListMode;

use self::common::passphrase_cb;

#[macro_use]
mod common;

test_case! {
    test_sign_key(test) {
        let mut ctx = test.create_context();
        if !ctx.engine_info().check_version("2.1.12") {
            return;
        }

        ctx.add_key_list_mode(KeyListMode::SIGS).unwrap();
        let signer = ctx.find_secret_keys(Some("alfa@example.net")).unwrap().next().unwrap().unwrap();
        ctx.add_signer(&signer).unwrap();

        let mut key = ctx.find_keys(Some("bravo@example.net")).unwrap().next().unwrap().unwrap();
        assert!(!key.user_ids().next().unwrap().signatures().any(|s| {
            signer.id_raw() == s.signer_key_id_raw()
        }));

        ctx.with_passphrase_provider(passphrase_cb, |ctx| {
            ctx.sign_key(&key, None::<String>, Default::default()).unwrap();
        });

        key.update().unwrap();
        assert!(key.user_ids().next().unwrap().signatures().any(|s| {
            signer.id_raw() == s.signer_key_id_raw()
        }));
    }
}
