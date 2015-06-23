extern crate tempdir;
extern crate gpgme;

use std::io;
use std::io::prelude::*;

use tempdir::TempDir;

use gpgme::{Protocol, Data};
use gpgme::ops;

use self::support::{setup_agent, passphrase_cb};

#[macro_use]
mod support;

const TEXT: &'static str = "Hallo Leute\n";

fn setup() -> TempDir {
    let dir = TempDir::new(".test-gpgme").unwrap();
    setup_agent(dir.path());
    dir
}

#[test]
fn test_symmetric() {
    let _gpghome = setup();
    let mut ctx = fail_if_err!(gpgme::create_context());
    ctx.set_protocol(Protocol::OpenPgp).unwrap();
    let mut guard = ctx.with_passphrase_cb(passphrase_cb);

    let mut plain = fail_if_err!(Data::from_buffer(TEXT));
    let mut cipher = fail_if_err!(Data::new());
    fail_if_err!(guard.encrypt(None, ops::EncryptFlags::empty(), &mut plain, &mut cipher));

    cipher.seek(io::SeekFrom::Start(0)).unwrap();
    plain = fail_if_err!(Data::new());
    fail_if_err!(guard.decrypt(&mut cipher, &mut plain));
    assert_eq!(plain.into_bytes().unwrap(), TEXT.as_bytes());
}
