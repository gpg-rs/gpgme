use sealed_test::prelude::*;

#[macro_use]
mod common;

#[sealed_test]
fn test_key_list() {
    common::with_test_harness(|| {
        let mut ctx = common::create_context();
        let keys: Vec<_> = ctx
            .find_keys(Some("alfa@example.net"))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(keys.len(), 1, "incorrect number of keys");

        let key = &keys[0];
        assert_eq!(key.id(), Ok("2D727CC768697734"));
        assert_eq!(key.subkeys().count(), 2);
        let subkeys: Vec<_> = key.subkeys().collect();
        assert_eq!(subkeys[0].algorithm(), gpgme::KeyAlgorithm::Dsa);
        assert_eq!(subkeys[1].algorithm(), gpgme::KeyAlgorithm::ElgamalEncrypt);
    })
}
