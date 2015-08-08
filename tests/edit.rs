extern crate tempdir;
extern crate gpgme;

use std::io::prelude::*;

use gpgme::{Data, Result};
use gpgme::context::EditCallback;
use gpgme::edit::{self, StatusCode};

use self::support::{setup, passphrase_cb};

#[macro_use]
mod support;

struct TestEditCallback {
    step: u32,
}

impl EditCallback for TestEditCallback {
    fn call(&mut self, _status: StatusCode, args: Option<&str>,
            output: &mut Write) -> Result<()> {
        let result = if args == Some(edit::PROMPT) {
            let step = self.step;
            self.step += 1;
            match step {
                0 => Some("fpr"),
                1 => Some("expire"),
                2 => Some("1"),
                3 => Some("primary"),
                _ => Some("quit"),
            }
        } else if args == Some(edit::CONFIRM_SAVE) {
            Some("Y")
        } else if args == Some(edit::KEY_VALID) {
            Some("0")
        } else {
            None
        };
        if let Some(result) = result {
            try!(write!(output, "{}\n", result));
        }
        Ok(())
    }
}

#[test]
fn test_edit() {
    let _gpghome = setup();
    let mut ctx = fail_if_err!(gpgme::create_context());
    fail_if_err!(ctx.set_protocol(gpgme::PROTOCOL_OPENPGP));
    let mut guard = ctx.with_passphrase_cb(passphrase_cb);

    let key = fail_if_err!(guard.find_keys(Some("Alpha"))).next().unwrap().unwrap();
    let mut output = fail_if_err!(Data::new());
    fail_if_err!(guard.edit_key(&key, TestEditCallback { step: 0 }, &mut output));
}
