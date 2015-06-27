extern crate tempdir;
extern crate gpgme;

use std::io;
use std::io::prelude::*;

use gpgme::{Protocol, SignatureNotationFlags, Data};
use gpgme::ops;

use self::support::{setup, passphrase_cb};

#[macro_use]
mod support;

fn check_result(result: ops::VerifyResult, expected: &mut [(&str, &str, SignatureNotationFlags, u32)]) {
    assert_eq!(result.signatures().count(), 1);
    let signature = result.signatures().next().unwrap();
    for notation in signature.notations() {
        match expected.iter_mut().find(|&&mut (name, value, flags, _)| {
            (notation.name().unwrap_or("") == name) &&
            (notation.value().unwrap_or("") == value) &&
            (notation.flags() == (flags & !gpgme::NOTATION_CRITICAL)) &&
            (notation.is_human_readable() == !(flags & gpgme::NOTATION_HUMAN_READABLE).is_empty()) &&
            !notation.is_critical()
        }) {
            Some(v) => v.3 += 1,
            None => {
                panic!("Unexpected notation data: {:?}: {:?} ({:?})", notation.name(),
                       notation.value(), notation.flags());
            }
        }
    }
    for notation in expected.iter() {
        assert_eq!(notation.3, 1);
    }
}

#[test]
fn test_notations() {
    let _gpghome = setup();
    let mut ctx = fail_if_err!(gpgme::create_context());
    fail_if_err!(ctx.set_protocol(Protocol::OpenPgp));
    let mut guard = ctx.with_passphrase_cb(passphrase_cb);

    guard.set_armor(true);
    guard.set_text_mode(true);

    let mut expected = [("laughing@me", "Just Squeeze Me", gpgme::NOTATION_HUMAN_READABLE, 0),
                        ("preferred-email-encoding@pgp.com", "pgpmime",
                         gpgme::NOTATION_HUMAN_READABLE | gpgme::NOTATION_CRITICAL, 0),
                        ("", "http://www.gnu.org/policy/",
                         gpgme::SignatureNotationFlags::empty(), 0)];
    guard.clear_notations();
    for notation in expected.iter() {
        if !notation.0.is_empty() {
            fail_if_err!(guard.add_notation(notation.0, notation.1, notation.2));
        } else {
            fail_if_err!(guard.add_policy_url(notation.1, notation.2
                                              .contains(gpgme::NOTATION_CRITICAL)));
        };
    }

    let mut input = fail_if_err!(Data::from_buffer(b"Hallo Leute\n"));
    let mut output = fail_if_err!(Data::new());
    fail_if_err!(guard.sign_normal(&mut input, &mut output));

    input = fail_if_err!(Data::new());
    output.seek(io::SeekFrom::Start(0)).unwrap();
    check_result(fail_if_err!(guard.verify_opaque(&mut output, &mut input)),
                 &mut expected);
}
