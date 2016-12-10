extern crate tempdir;
extern crate gpgme;

use std::io::prelude::*;

use gpgme::{Data, Error, Result};
use gpgme::error;
use gpgme::edit::{self, Editor, EditStatus};

use self::support::{setup, passphrase_cb};

#[macro_use]
mod support;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum TestEditorState {
    Start,
    Fingerprint,
    Expire,
    Valid,
    Uid,
    Primary,
    Quit,
    Save,
}

struct TestEditor;

impl Editor for TestEditor {
    type State = TestEditorState;

    fn start() -> Self::State {
        TestEditorState::Start
    }

    fn next_state(state: Result<Self::State>, status: EditStatus) -> Result<Self::State> {
        use self::TestEditorState as State;

        println!("[-- Code: {:?}, {:?} --]", status.code, status.args());
        if !status.code.is_command() {
            return state;
        }

        if status.args() == Ok(edit::PROMPT) {
            match state {
                Ok(State::Start) => Ok(State::Fingerprint),
                Ok(State::Fingerprint) => Ok(State::Expire),
                Ok(State::Valid) => Ok(State::Uid),
                Ok(State::Uid) => Ok(State::Primary),
                Ok(State::Quit) => state,
                Ok(State::Primary) | Err(_) => Ok(State::Quit),
                _ => Err(Error::from_code(error::GPG_ERR_GENERAL)),
            }
        } else if (status.args() == Ok(edit::KEY_VALID)) && (state == Ok(State::Expire)) {
            Ok(State::Valid)
        } else if (status.args() == Ok(edit::CONFIRM_SAVE)) && (state == Ok(State::Quit)) {
            Ok(State::Save)
        } else {
            state.and(Err(Error::from_code(error::GPG_ERR_GENERAL)))
        }
    }

    fn action<W: Write>(&self, state: Self::State, mut out: W) -> Result<()> {
        use self::TestEditorState as State;

        match state {
            State::Fingerprint => try!(out.write_all(b"fpr")),
            State::Expire => try!(out.write_all(b"expire")),
            State::Valid => try!(out.write_all(b"0")),
            State::Uid => try!(out.write_all(b"1")),
            State::Primary => try!(out.write_all(b"primary")),
            State::Quit => try!(write!(out, "{}", edit::QUIT)),
            State::Save => try!(write!(out, "{}", edit::YES)),
            _ => return Err(Error::from_code(error::GPG_ERR_GENERAL)),
        }
        Ok(())
    }
}

#[test]
fn test_edit() {
    let _gpghome = setup();
    if !gpgme::init().check_version("1.4.3") {
        return;
    }

    let mut ctx = fail_if_err!(gpgme::create_context());
    fail_if_err!(ctx.set_protocol(gpgme::PROTOCOL_OPENPGP));
    ctx.with_passphrase_handler(passphrase_cb, |mut ctx| {
        let key = fail_if_err!(ctx.find_keys(Some("Alpha"))).next().unwrap().unwrap();
        let mut output = fail_if_err!(Data::new());
        fail_if_err!(ctx.edit_key_with(&key, TestEditor, &mut output));
    });
}
