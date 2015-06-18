extern crate tempdir;
extern crate gpgme;

use gpgme::{Protocol, Key, KeyAlgorithm, Validity};

use self::support::setup;

mod support;

struct Uid {
    name: &'static str,
    comment: &'static str,
    email: &'static str,
}

struct KeyInfo {
    fpr: &'static str,
    sec_keyid: &'static str,
    uid: [Option<Uid>; 3],
    n_subkeys: usize,
    misc_check: Option<fn(&KeyInfo, &Key)>,
}

const KEY_INFOS: [KeyInfo; 26] = [
    KeyInfo {
        fpr: "A0FF4590BB6122EDEF6E3C542D727CC768697734",
        sec_keyid: "6AE6D7EE46A871F8",
        uid: [Some(Uid { name: "Alfa Test",
                       comment: "demo key",
                       email: "alfa@example.net" }),
              Some(Uid { name: "Alpha Test",
                       comment: "demo key",
                       email: "alpha@example.net" }),
              Some(Uid { name: "Alice",
                       comment: "demo key",
                       email: "" })],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr: "D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2",
        sec_keyid: "5381EA4EE29BA37F",
        uid: [Some(Uid { name: "Bob",
                       comment: "demo key",
                       email: "" }),
              Some(Uid { name: "Bravo Test",
                       comment: "demo key",
                       email: "bravo@example.net" }),
              None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr: "61EE841A2A27EB983B3B3C26413F4AF31AFDAB6C",
        sec_keyid: "E71E72ACBC43DA60",
        uid: [Some(Uid { name: "Charlie Test",
                       comment: "demo key",
                       email: "charlie@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr: "6560C59C43D031C54D7C588EEBA9F240EB9DC9E6",
        sec_keyid: "06F22880B0C45424",
        uid: [Some(Uid { name: "Delta Test",
                       comment: "demo key",
                       email: "delta@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr:  "3531152DE293E26A07F504BC318C1FAEFAEF6D1B",
        sec_keyid: "B5C79E1A7272144D",
        uid: [Some(Uid { name: "Echelon",
                       comment: "demo key",
                       email: "" }),
              Some(Uid { name: "Echo Test",
                       comment: "demo key",
                       email: "echo@example.net" }),
              Some(Uid { name: "Eve",
                       comment: "demo key",
                       email: "" })],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr: "56D33268F7FE693FBB594762D4BF57F37372E243",
        sec_keyid: "0A32EE79EE45198E",
        uid: [Some(Uid { name: "Foxtrot Test",
                       comment: "demo key",
                       email: "foxtrot@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr: "C9C07DCC6621B9FB8D071B1D168410A48FC282E6",
        sec_keyid: "247491CC9DCAD354",
        uid: [Some(Uid { name: "Golf Test",
                       comment: "demo key",
                       email: "golf@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr: "9E91CBB11E4D4135583EF90513DB965534C6E3F1",
        sec_keyid: "76E26537D622AD0A",
        uid: [Some(Uid { name: "Hotel Test",
                       comment: "demo key",
                       email: "hotel@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr: "CD538D6CC9FB3D745ECDA5201FE8FC6F04259677",
        sec_keyid: "C1C8EFDE61F76C73",
        uid: [Some(Uid { name: "India Test",
                       comment: "demo key",
                       email: "india@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr:  "F8F1EDC73995AB739AD54B380C820C71D2699313",
        sec_keyid: "BD0B108735F8F136",
        uid: [Some(Uid { name: "Juliet Test",
                       comment: "demo key",
                       email: "juliet@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr:  "3FD11083779196C2ECDD9594AD1B0FAD43C2D0C7",
        sec_keyid: "86CBB34A9AF64D02",
        uid: [Some(Uid { name: "Kilo Test",
                       comment: "demo key",
                       email: "kilo@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr:  "1DDD28CEF714F5B03B8C246937CAB51FB79103F8",
        sec_keyid: "0363B449FE56350C",
        uid: [Some(Uid { name: "Lima Test",
                       comment: "demo key",
                       email: "lima@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr: "2686AA191A278013992C72EBBE794852BE5CF886",
        sec_keyid: "5F600A834F31EAE8",
        uid: [Some(Uid { name: "Mallory",
                       comment: "demo key",
                       email: "" }),
              Some(Uid { name: "Mike Test",
                       comment: "demo key",
                       email: "mike@example.net" }),
              None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr:  "5AB9D6D7BAA1C95B3BAA3D9425B00FD430CEC684",
        sec_keyid: "4C1D63308B70E472",
        uid: [Some(Uid { name: "November Test",
                       comment: "demo key",
                       email: "november@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr:  "43929E89F8F79381678CAE515F6356BA6D9732AC",
        sec_keyid: "FF0785712681619F",
        uid: [Some(Uid { name: "Oscar Test",
                       comment: "demo key",
                       email: "oscar@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr:  "6FAA9C201E5E26DCBAEC39FD5D15E01D3FF13206",
        sec_keyid: "2764E18263330D9C",
        uid: [Some(Uid { name: "Papa test",
                       comment: "demo key",
                       email: "papa@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr:  "A7969DA1C3297AA96D49843F1C67EC133C661C84",
        sec_keyid: "6CDCFC44A029ACF4",
        uid: [Some(Uid { name: "Quebec Test",
                       comment: "demo key",
                       email: "quebec@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr:  "38FBE1E4BF6A5E1242C8F6A13BDBEDB1777FBED3",
        sec_keyid: "9FAB805A11D102EA",
        uid: [Some(Uid { name: "Romeo Test",
                       comment: "demo key",
                       email: "romeo@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr:  "045B2334ADD69FC221076841A5E67F7FA3AE3EA1",
        sec_keyid: "93B88B0F0F1B50B4",
        uid: [Some(Uid { name: "Sierra Test",
                       comment: "demo key",
                       email: "sierra@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr:  "ECAC774F4EEEB0620767044A58CB9A4C85A81F38",
        sec_keyid: "97B60E01101C0402",
        uid: [Some(Uid { name: "Tango Test",
                       comment: "demo key",
                       email: "tango@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr:  "0DBCAD3F08843B9557C6C4D4A94C0F75653244D6",
        sec_keyid: "93079B915522BDB9",
        uid: [Some(Uid { name: "Uniform Test",
                       comment: "demo key",
                       email: "uniform@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr:  "E8143C489C8D41124DC40D0B47AF4B6961F04784",
        sec_keyid: "04071FB807287134",
        uid: [Some(Uid { name: "Victor Test",
                       comment: "demo key",
                       email: "victor@example.org" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr:  "E8D6C90B683B0982BD557A99DEF0F7B8EC67DBDE",
        sec_keyid: "D7FBB421FD6E27F6",
        uid: [Some(Uid { name: "Whisky Test",
                       comment: "demo key",
                       email: "whisky@example.net" }),
              None, None],
        n_subkeys: 3,
        misc_check: Some(check_whisky),
    },
    KeyInfo {
        fpr:  "04C1DF62EFA0EBB00519B06A8979A6C5567FB34A",
        sec_keyid: "5CC6F87F41E408BE",
        uid: [Some(Uid { name: "XRay Test",
                       comment: "demo key",
                       email: "xray@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr:  "ED9B316F78644A58D042655A9EEF34CD4B11B25F",
        sec_keyid: "5ADFD255F7B080AD",
        uid: [Some(Uid { name: "Yankee Test",
                       comment: "demo key",
                       email: "yankee@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
    KeyInfo {
        fpr:  "23FD347A419429BACCD5E72D6BC4778054ACD246",
        sec_keyid: "EF9DC276A172C881",
        uid: [Some(Uid { name: "Zulu Test",
                       comment: "demo key",
                       email: "zulu@example.net" }),
              None, None],
        n_subkeys: 1,
        misc_check: None,
    },
];

fn check_whisky(_info: &KeyInfo, key: &Key) {
    let sub1 = key.subkeys().nth(2).unwrap();
    let sub2 = key.subkeys().nth(3).unwrap();

    assert!(sub1.is_expired());
    assert!(sub2.is_expired());
    assert_eq!(sub1.expires(), Some(1129636886));
    assert_eq!(sub2.expires(), Some(1129636939));
}

#[test]
fn test_keylist() {
    let _gpghome = setup();
    let mut ctx = gpgme::create_context().unwrap();
    ctx.set_protocol(Protocol::OpenPgp).unwrap();

    let mut i = 0;
    let mut keys = ctx.keys().unwrap();
    for key in keys.by_ref().filter_map(Result::ok) {
        assert!(i < KEY_INFOS.len());
        assert!(!key.is_revoked());
        assert!(!key.is_expired());
        assert!(!key.is_disabled());
        assert!(!key.is_invalid());
        assert!(key.can_sign());
        assert!(key.can_certify());
        assert!(!key.is_secret());
        assert_eq!(key.protocol(), Protocol::OpenPgp);
        assert_eq!(key.issuer_serial(), None);
        assert_eq!(key.issuer_name(), None);
        assert_eq!(key.chain_id(), None);
        assert_eq!(key.owner_trust(), Validity::Unknown);

        let info = &KEY_INFOS[i];
        assert_eq!(key.subkeys().count() - 1, info.n_subkeys);

        let primary = key.primary_key().unwrap();
        assert!(!primary.is_revoked());
        assert!(!primary.is_expired());
        assert!(!primary.is_disabled());
        assert!(!primary.is_invalid());
        assert!(!primary.can_encrypt());
        assert!(primary.can_sign());
        assert!(primary.can_certify());
        assert!(!primary.is_secret());
        assert!(!primary.is_cardkey());
        assert_eq!(primary.card_number(), None);
        assert_eq!(primary.algorithm(), KeyAlgorithm::Dsa);
        assert_eq!(primary.length(), 1024);
        assert_eq!(primary.id(), Some(&info.fpr[24..]));
        assert_eq!(primary.fingerprint(), Some(info.fpr));
        assert_eq!(primary.expires(), None);

        let secondary = key.subkeys().nth(1).unwrap();
        assert!(!secondary.is_revoked());
        assert!(!secondary.is_expired());
        assert!(!secondary.is_disabled());
        assert!(!secondary.is_invalid());
        assert!(secondary.can_encrypt());
        assert!(!secondary.can_sign());
        assert!(!secondary.can_certify());
        assert!(!secondary.is_secret());
        assert!(!secondary.is_cardkey());
        assert_eq!(secondary.card_number(), None);
        assert_eq!(secondary.algorithm(), KeyAlgorithm::ElGamalEncrypt);
        assert_eq!(secondary.length(), 1024);
        assert_eq!(secondary.id(), Some(info.sec_keyid));
        assert!(secondary.fingerprint().is_some());
        assert_eq!(secondary.expires(), None);

        assert_eq!(key.user_ids().count(), info.uid.iter().filter(|u| u.is_some()).count());
        for (actual, expected) in key.user_ids().zip(info.uid.iter().filter_map(|u| u.as_ref())) {
            assert!(!actual.is_revoked());
            assert!(!actual.is_invalid());
            assert_eq!(actual.validity(), Validity::Unknown);
            assert!(actual.signatures().next().is_none());
            assert_eq!(actual.name().unwrap_or(""), expected.name);
            assert_eq!(actual.email().unwrap_or(""), expected.email);
            assert_eq!(actual.comment().unwrap_or(""), expected.comment);
        }

        match info.misc_check {
            Some(f) => f(info, &key),
            None => (),
        }
        i += 1;
    }
    assert!(!keys.result().unwrap().truncated());
    assert_eq!(i, KEY_INFOS.len());
}
