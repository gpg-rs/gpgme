extern crate tempdir;
extern crate gpgme;

use gpgme::Data;
use gpgme::ops;

use self::support::setup;

#[macro_use]
mod support;

const PUBKEY_1: &'static [u8] = include_bytes!("./data/pubkey-1.asc");
const SECKEY_1: &'static [u8] = include_bytes!("./data/seckey-1.asc");

const FINGERPRINT: &'static str = "ADAB7FCC1F4DE2616ECFA402AF82244F9CD9FD55";

fn check_result(result: ops::ImportResult, secret: bool) {
    if !secret {
        assert_eq!(result.considered(), 1);
    } else if result.considered() != 3 {
        assert_eq!(result.considered(), 1);
    }
    assert_eq!(result.no_user_id(), 0);
    if secret {
        assert_eq!(result.imported(), 0);
    } else if result.imported() != 0 {
        assert_eq!(result.imported(), 1);
    }
    assert_eq!(result.imported_rsa(), 0);
    if secret {
        if result.unchanged() != 0 {
            assert_eq!(result.unchanged(), 1);
        }
    } else if result.imported() > 0 {
        assert_eq!(result.unchanged(), 0);
    } else {
        assert_eq!(result.unchanged(), 1);
    }
    assert_eq!(result.new_user_ids(), 0);
    assert_eq!(result.new_subkeys(), 0);
    assert_eq!(result.new_revocations(), 0);

    if !secret {
        assert_eq!(result.secret_read(), 0);
    } else if result.secret_read() != 3 {
        assert_eq!(result.secret_read(), 1);
    }
    if !secret || ((result.secret_imported() != 1) && (result.secret_imported() != 2)) {
        assert_eq!(result.secret_imported(), 0);
    }
    if !secret {
        assert_eq!(result.secret_unchanged(), 0);
    } else if result.secret_imported() > 0 {
        assert_eq!(result.secret_unchanged(), 0);
    } else if result.secret_unchanged() != 1 {
        assert_eq!(result.secret_unchanged(), 2);
    }
    assert_eq!(result.not_imported(), 0);

    let filter_imports = |p: &ops::ImportStatus| -> bool {
        p.status().contains(ops::IMPORT_NEW) || p.status().contains(ops::IMPORT_SIG) ||
            p.status().contains(ops::IMPORT_UID)
    };

    let count = result.imports().filter(&filter_imports).count();
    if !secret || (count != 2) {
        assert_eq!(count, 1);
    }

    for import in result.imports().filter(&filter_imports) {
        assert_eq!(import.fingerprint(), Some(FINGERPRINT));
        assert_eq!(import.result(), Ok(()));
    }
}

#[test]
fn test_import() {
    let _gpghome = setup();
    let mut ctx = fail_if_err!(gpgme::create_context());
    fail_if_err!(ctx.set_protocol(gpgme::PROTOCOL_OPENPGP));

    let mut input = fail_if_err!(Data::from_buffer(PUBKEY_1));
    check_result(fail_if_err!(ctx.import(&mut input)), false);

    input = fail_if_err!(Data::from_buffer(SECKEY_1));
    check_result(fail_if_err!(ctx.import(&mut input)), true);
}
