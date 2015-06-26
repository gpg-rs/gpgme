extern crate tempdir;
extern crate gpgme;

use std::io::prelude::*;

use gpgme::{Error, Result};
use gpgme::{Protocol, StatusCode, EditorState, Editor, EditorWrapper, Data};
use gpgme::error;
use gpgme::edit::{self, KeyWord};

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
    Error,
}

impl EditorState for TestEditorState {
    fn start() -> Self {
        TestEditorState::Start
    }

    fn error() -> Self {
        TestEditorState::Error
    }
}

struct TestEditor;

impl Editor for TestEditor {
    type State = TestEditorState;

    fn next_state<'a>(wrapper: &EditorWrapper<Self>, status: StatusCode,
                  args: KeyWord<'a>) -> Result<Self::State> {
        if status.can_ignore() {
            return Ok(wrapper.state());
        }

        println!("[-- Code: {:?}, {:?} --]", status, args);
        let err_general = Err(Error::from_code(error::GPG_ERR_GENERAL));
        match wrapper.state() {
            TestEditorState::Start => {
                if (status == StatusCode::GetLine) && (args == KeyWord::Prompt) {
                    Ok(TestEditorState::Fingerprint)
                } else if status == StatusCode::ImportOk {
                    Ok(TestEditorState::Start)
                } else {
                    err_general
                }
            },
            TestEditorState::Fingerprint => {
                if (status == StatusCode::GetLine) && (args == KeyWord::Prompt) {
                    Ok(TestEditorState::Expire)
                } else {
                    err_general
                }
            },
            TestEditorState::Expire => {
                if (status == StatusCode::GetLine) && (args == KeyWord::KeyValid) {
                    Ok(TestEditorState::Valid)
                } else {
                    err_general
                }
            },
            TestEditorState::Valid => {
                if (status == StatusCode::GetLine) && (args == KeyWord::Prompt) {
                    Ok(TestEditorState::Uid)
                } else {
                    err_general
                }
            },
            TestEditorState::Uid => {
                if (status == StatusCode::GetLine) && (args == KeyWord::Prompt) {
                    Ok(TestEditorState::Primary)
                } else {
                    err_general
                }
            },
            TestEditorState::Primary => {
                if (status == StatusCode::GetLine) && (args == KeyWord::Prompt) {
                    Ok(TestEditorState::Quit)
                } else {
                    err_general
                }
            },
            TestEditorState::Quit => {
                if (status == StatusCode::GetBool) && (args == KeyWord::ConfirmSave) {
                    Ok(TestEditorState::Save)
                } else {
                    err_general
                }
            },
            TestEditorState::Error => {
                if (status == StatusCode::GetLine) && (args == KeyWord::Prompt) {
                    Ok(TestEditorState::Quit)
                } else {
                    Err(wrapper.last_error())
                }
            },
            _ => err_general,
        }
    }

    fn action(&self, state: Self::State, out: &mut Write) -> Result<()> {
        match state {
            TestEditorState::Fingerprint => try!(out.write_all(b"fpr")),
            TestEditorState::Expire => try!(out.write_all(b"expire")),
            TestEditorState::Valid => try!(out.write_all(b"0")),
            TestEditorState::Uid => try!(out.write_all(b"1")),
            TestEditorState::Primary => try!(out.write_all(b"primary")),
            TestEditorState::Quit => try!(out.write_all(edit::QUIT.as_bytes())),
            TestEditorState::Save => try!(out.write_all(edit::YES.as_bytes())),
            _ => return Err(Error::from_code(error::GPG_ERR_GENERAL)),
        }
        Ok(())
    }
}

#[test]
fn test_edit() {
    let _gpghome = setup();
    let mut ctx = fail_if_err!(gpgme::create_context());
    fail_if_err!(ctx.set_protocol(Protocol::OpenPgp));
    let mut guard = ctx.with_passphrase_cb(passphrase_cb);

    let key = fail_if_err!(guard.find_keys(Some("Alpha"))).next().unwrap().unwrap();
    let mut output = fail_if_err!(Data::new());
    fail_if_err!(guard.edit_key(&key, TestEditor, &mut output));
}
