use std::time::{Duration, SystemTime};

use gpgme::{require_gpgme_ver, CreateKeyFlags};

use self::common::passphrase_cb;

#[macro_use]
mod common;

test_case! {
    #[requires((1, 7))]
    test_create_key(test) {
        let mut ctx = test.create_context().set_passphrase_provider(passphrase_cb);
        if !ctx.engine_info().check_version("2.1.13") {
            return;
        }

        let expiration = Duration::from_secs(3600);
        let res = ctx.create_key_with_flags("test user <test@example.com>",
            "future-default", expiration, CreateKeyFlags::CERT).unwrap();
        let creation = SystemTime::now();

        let fpr = res.fingerprint_raw().unwrap();
        assert!(res.has_primary_key());
        let mut key = ctx.get_key(fpr).unwrap();
        assert!(!key.is_bad());
        assert!(key.can_certify());
        assert!(!key.can_sign());
        assert!(!key.can_encrypt());
        assert!(!key.can_authenticate());

        let primary = key.primary_key().unwrap();
        assert!(!primary.is_bad());
        assert!(primary.can_certify());
        assert!(!primary.can_sign());
        assert!(!primary.can_encrypt());
        assert!(!primary.can_authenticate());
        assert!(primary.expiration_time().unwrap().duration_since(creation).unwrap() <= expiration);

        assert_eq!(key.subkeys().count(), 1);
        assert_eq!(key.user_ids().count(), 1);
        let uid = key.user_ids().nth(0).unwrap();
        assert!(!uid.is_bad());
        assert_eq!(uid.name(), Ok("test user"));
        assert_eq!(uid.email(), Ok("test@example.com"));
        assert_eq!(uid.id(), Ok("test user <test@example.com>"));

        let res = ctx.create_subkey_with_flags(&key, "future-default", expiration,
            CreateKeyFlags::AUTH).unwrap();
        let creation = SystemTime::now();
        assert!(res.has_sub_key());
        key.update().unwrap();
        assert!(key.can_authenticate());
        assert_eq!(key.subkeys().count(), 2);

        let sub = key.subkeys().find(|k| k.fingerprint_raw() == res.fingerprint_raw()).unwrap();
        assert!(!sub.is_bad());
        assert!(!sub.can_certify());
        assert!(!sub.can_sign());
        assert!(!sub.can_encrypt());
        assert!(sub.can_authenticate());
        assert!(sub.expiration_time().unwrap().duration_since(creation).unwrap() <= expiration);

        let res = ctx.create_subkey_with_flags(&key, "future-default", expiration,
            CreateKeyFlags::ENCR | CreateKeyFlags::NOEXPIRE).unwrap();
        assert!(res.has_sub_key());
        key.update().unwrap();
        assert!(key.can_authenticate());
        assert_eq!(key.subkeys().count(), 3);

        let sub = key.subkeys().find(|k| k.fingerprint_raw() == res.fingerprint_raw()).unwrap();
        assert!(!sub.is_bad());
        assert!(!sub.can_certify());
        assert!(!sub.can_sign());
        assert!(sub.can_encrypt());
        assert!(!sub.can_authenticate());
        assert_eq!(sub.expiration_time(), None);
    }
}
