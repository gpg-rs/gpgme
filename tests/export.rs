use gpgme::{CreateKeyFlags, ExportMode};

use self::common::passphrase_cb;

#[macro_use]
mod common;

test_case! {
    test_export(test) {
        let mut ctx = test.create_context().set_passphrase_provider(passphrase_cb);
        ctx.set_offline(true);
        ctx.set_armor(true);

        let key = ctx.find_keys(Some("alfa@example.net")).unwrap().next().unwrap().unwrap();

        let mut data = Vec::new();
        ctx.export(key.fingerprint_raw(), ExportMode::empty(), &mut data).unwrap();
        assert!(!data.is_empty());
    }

    test_export_secret(test) {
        let mut ctx = test.create_context();
        ctx.set_offline(true);
        ctx.set_armor(true);

        let res = match ctx.create_key_with_flags("test user <test@example.com>",
            "future-default", Default::default(), CreateKeyFlags::NOPASSWD) {
            Ok(r) => r,
            Err(e) if e.code() == gpgme::Error::NOT_SUPPORTED.code() => return,
            Err(e) => panic!("error: {:?}", e),
        };
        let fpr = res.fingerprint_raw().unwrap();

        let mut data = Vec::new();
        ctx.export(Some(fpr), ExportMode::SECRET, &mut data).unwrap();
        assert!(!data.is_empty());
    }
}
