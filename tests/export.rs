use gpgme::{ExportMode, CreateKeyFlags};

use self::common::passphrase_cb;

#[macro_use]
mod common;

test_case! {
    test_export(test) {
        let mut ctx = test.create_context().set_passphrase_provider(passphrase_cb);
        ctx.set_offline(true);
        ctx.set_armor(true);

        let key = ctx.find_keys(Some("alfa@example.net")).unwrap().nth(0).unwrap().unwrap();

        let mut data = Vec::new();
        ctx.export(key.fingerprint_raw(), ExportMode::empty(), &mut data).unwrap();
        assert!(!data.is_empty());
    }

    #[requires((1, 7))]
    test_export_secret(test) {
        let mut ctx = test.create_context();
        ctx.set_offline(true);
        ctx.set_armor(true);

        let res = ctx.create_key_with_flags("test user <test@example.com>",
            "future-default", Default::default(), CreateKeyFlags::NOPASSWD).unwrap();
        let fpr = res.fingerprint_raw().unwrap();

        let mut data = Vec::new();
        ctx.export(Some(fpr), ExportMode::SECRET, &mut data).unwrap();
        assert!(!data.is_empty());
    }
}
