extern crate tempdir;
extern crate gpgme;

use std::io;
use std::io::prelude::*;

use gpgme::{ErrorCode, Protocol, Validity, Data};
use gpgme::error;
use gpgme::ops;

use self::support::setup;

#[macro_use]
mod support;

const TEST_TEXT1: &'static [u8] = b"Just GNU it!\n";
const TEST_TEXT1F: &'static [u8] = b"Just GNU it?\n";
const TEST_SIG1: &'static [u8] = b"-----BEGIN PGP SIGNATURE-----\n\n\
iN0EABECAJ0FAjoS+i9FFIAAAAAAAwA5YmFyw7bDpMO8w58gZGFzIHdhcmVuIFVt\n\
bGF1dGUgdW5kIGpldHp0IGVpbiBwcm96ZW50JS1aZWljaGVuNRSAAAAAAAgAJGZv\n\
b2Jhci4xdGhpcyBpcyBhIG5vdGF0aW9uIGRhdGEgd2l0aCAyIGxpbmVzGhpodHRw\n\
Oi8vd3d3Lmd1Lm9yZy9wb2xpY3kvAAoJEC1yfMdoaXc0JBIAoIiLlUsvpMDOyGEc\n\
dADGKXF/Hcb+AKCJWPphZCphduxSvrzH0hgzHdeQaA==\n\
=nts1\n\
-----END PGP SIGNATURE-----\n";

const TEST_SIG2: &'static [u8] = b"-----BEGIN PGP MESSAGE-----\n\n\
owGbwMvMwCSoW1RzPCOz3IRxjXQSR0lqcYleSUWJTZOvjVdpcYmCu1+oQmaJIleH\n\
GwuDIBMDGysTSIqBi1MApi+nlGGuwDeHao53HBr+FoVGP3xX+kvuu9fCMJvl6IOf\n\
y1kvP4y+8D5a11ang0udywsA\n\
=Crq6\n\
-----END PGP MESSAGE-----\n";

/* A message with a prepended but unsigned plaintext packet. */
const DOUBLE_PLAINTEXT_SIG: &'static [u8] = b"-----BEGIN PGP MESSAGE-----\n\n\
rDRiCmZvb2Jhci50eHRF4pxNVGhpcyBpcyBteSBzbmVha3kgcGxhaW50ZXh0IG1l\n\
c3NhZ2UKowGbwMvMwCSoW1RzPCOz3IRxTWISa6JebnG666MFD1wzSzJSixQ81XMV\n\
UlITUxTyixRyKxXKE0uSMxQyEosVikvyCwpSU/S4FNCArq6Ce1F+aXJGvoJvYlGF\n\
erFCTmJxiUJ5flFKMVeHGwuDIBMDGysTyA4GLk4BmO036xgWzMgzt9V85jCtfDFn\n\
UqVooWlGXHwNw/xg/fVzt9VNbtjtJ/fhUqYo0/LyCGEA\n\
=6+AK\n\
-----END PGP MESSAGE-----\n";

fn check_result(result: ops::VerifyResult, fpr: &str, summary: ops::SignatureSummary,
                status: ErrorCode, notations: bool) {
    assert_eq!(result.signatures().count(), 1);

    let signature = result.signatures().next().unwrap();
    assert_eq!(signature.summary(), summary);
    assert_eq!(signature.fingerprint(), Some(fpr));
    assert_eq!(signature.status().code(), status);
    assert!(!signature.wrong_key_usage());
    assert_eq!(signature.validity(), Validity::Unknown);
    assert_eq!(signature.validity_reason().code(), 0);

    if notations {
        let mut expected = [("bar", "öäüß das waren Umlaute und \
                             jetzt ein prozent%-Zeichen", 0),
                            ("foobar.1", "this is a notation data with 2 lines", 0),
                            ("", "http://www.gu.org/policy/", 0)];
        for notation in signature.notations() {
            match expected.iter_mut().find(|&&mut (name, value, _)| {
                (notation.name().unwrap_or("") == name) &&
                (notation.value().unwrap_or("") == value)
            }) {
                Some(v) => v.2 += 1,
                None => {
                    panic!("Unexpected notation data: {:?}: {:?}", notation.name(),
                           notation.value());
                }
            }
        }
        for notation in expected.iter() {
            assert_eq!(notation.2, 1);
        }
    }
}

#[test]
fn test_verify() {
    let _gpghome = setup();
    let mut ctx = fail_if_err!(gpgme::create_context());
    fail_if_err!(ctx.set_protocol(Protocol::OpenPgp));

    let mut text = fail_if_err!(Data::from_buffer(TEST_TEXT1));
    let mut sig = fail_if_err!(Data::from_buffer(TEST_SIG1));
    check_result(fail_if_err!(ctx.verify(&mut sig, Some(&mut text), None)),
        "A0FF4590BB6122EDEF6E3C542D727CC768697734", ops::SignatureSummary::empty(), 0, true);

    text = fail_if_err!(Data::from_buffer(TEST_TEXT1F));
    sig.seek(io::SeekFrom::Start(0)).unwrap();
    check_result(fail_if_err!(ctx.verify(&mut sig, Some(&mut text), None)),
        "2D727CC768697734", ops::SIGNATURE_RED, error::GPG_ERR_BAD_SIGNATURE, false);

    text = fail_if_err!(Data::new());
    sig = fail_if_err!(Data::from_buffer(TEST_SIG2));
    check_result(fail_if_err!(ctx.verify(&mut sig, None, Some(&mut text))),
        "A0FF4590BB6122EDEF6E3C542D727CC768697734", ops::SignatureSummary::empty(), 0, false);

    text = fail_if_err!(Data::new());
    sig = fail_if_err!(Data::from_buffer(DOUBLE_PLAINTEXT_SIG));
    assert_eq!(ctx.verify(&mut sig, None, Some(&mut text)).err()
        .map_or(0, |err| err.code()), error::GPG_ERR_BAD_DATA);
}
