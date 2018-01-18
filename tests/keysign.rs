#[macro_use]
extern crate gpgme;
#[macro_use]
extern crate lazy_static;
extern crate tempdir;

use gpgme::KeyListMode;

use self::support::passphrase_cb;

#[macro_use]
mod support;

require_gpgme_ver! {
    (1, 7) => {
        test_case! {
            test_sign_key(test) {
                let mut ctx = test.create_context();
                if !ctx.engine_info().check_version("2.1.12") {
                    return;
                }

                fail_if_err!(ctx.add_key_list_mode(KeyListMode::SIGS));
                let signer = fail_if_err!(ctx.find_secret_keys(Some("alfa@example.net"))).nth(0).unwrap().unwrap();
                fail_if_err!(ctx.add_signer(&signer));

                let mut key = fail_if_err!(ctx.find_keys(Some("bravo@example.net"))).nth(0).unwrap().unwrap();
                assert!(!key.user_ids().nth(0).unwrap().signatures().any(|s| {
                    signer.id_raw() == s.signer_key_id_raw()
                }));

                ctx.with_passphrase_provider(passphrase_cb, |ctx| {
                    fail_if_err!(ctx.sign_key(&key, None::<String>, None));
                });

                fail_if_err!(key.update());
                assert!(key.user_ids().nth(0).unwrap().signatures().any(|s| {
                    signer.id_raw() == s.signer_key_id_raw()
                }));
            }
        }
    }
}
