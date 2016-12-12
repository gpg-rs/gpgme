extern crate tempdir;
extern crate gpgme;

use std::io;
use std::io::prelude::*;

use tempdir::TempDir;

use gpgme::{Context, Data};

use self::support::{passphrase_cb, setup_agent};

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
    let mut ctx = fail_if_err!(Context::from_protocol(gpgme::Protocol::OpenPgp));
    ctx.with_passphrase_provider(passphrase_cb, |mut ctx| {
        let mut plain = fail_if_err!(Data::from_buffer(TEXT));
        let mut cipher = fail_if_err!(Data::new());
        fail_if_err!(ctx.encrypt_symmetric(&mut plain, &mut cipher));

        cipher.seek(io::SeekFrom::Start(0)).unwrap();
        plain = fail_if_err!(Data::new());
        fail_if_err!(ctx.decrypt(&mut cipher, &mut plain));
        assert_eq!(plain.try_into_bytes().unwrap(), TEXT.as_bytes());
    });
}
