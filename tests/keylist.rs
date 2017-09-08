extern crate gpgme;
#[macro_use]
extern crate lazy_static;
extern crate tempdir;

#[macro_use]
mod support;

test_case! {
    test_single_key_list(test) {
        let mut ctx = test.create_context();
        let keys: Vec<_> = fail_if_err!(fail_if_err!(ctx.find_keys(Some("alfa@example.net")))
                                        .collect());
        assert_eq!(keys.len(), 1);

        let key = &keys[0];
        assert_eq!(key.id(), Ok("2D727CC768697734"));
        assert_eq!(key.subkeys().count(), 2);
        let subkeys: Vec<_> = key.subkeys().collect();
        assert_eq!(subkeys[0].algorithm(), gpgme::KeyAlgorithm::Dsa);
        assert_eq!(subkeys[1].algorithm(), gpgme::KeyAlgorithm::ElgamalEncrypt);
    },
}
