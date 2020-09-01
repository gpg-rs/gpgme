use gpgme::{require_gpgme_ver, KeyListMode};

use self::common::passphrase_cb;

#[macro_use]
mod common;

test_case! {
    #[requires((1, 7))]
    test_sign_key(test) {
        let mut ctx = test.create_context();
        if !ctx.engine_info().check_version("2.1.12") {
            return;
        }

        ctx.add_key_list_mode(KeyListMode::SIGS).unwrap();
        let signer = ctx.find_secret_keys(Some("alfa@example.net")).unwrap().nth(0).unwrap().unwrap();
        ctx.add_signer(&signer).unwrap();

        let mut key = ctx.find_keys(Some("bravo@example.net")).unwrap().nth(0).unwrap().unwrap();
        assert!(!key.user_ids().nth(0).unwrap().signatures().any(|s| {
            signer.id_raw() == s.signer_key_id_raw()
        }));

        ctx.with_passphrase_provider(passphrase_cb, |ctx| {
            ctx.sign_key(&key, None::<String>, Default::default()).unwrap();
        });

        key.update().unwrap();
        assert!(key.user_ids().nth(0).unwrap().signatures().any(|s| {
            signer.id_raw() == s.signer_key_id_raw()
        }));
    }
}
