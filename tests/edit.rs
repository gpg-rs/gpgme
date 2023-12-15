#![allow(deprecated)]
use std::io::{prelude::*, stdout};

use gpgme::{
    edit::{self, EditInteractionStatus, Editor},
    Error, Result,
};
use sealed_test::prelude::*;

use self::common::passphrase_cb;

#[macro_use]
mod common;

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
enum TestEditorState {
    #[default]
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

    fn next_state(
        state: Result<Self::State>,
        status: EditInteractionStatus<'_>,
        need_response: bool,
    ) -> Result<Self::State> {
        use self::TestEditorState as State;

        println!("[-- Code: {:?}, {:?} --]", status.code, status.args());
        if !need_response {
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
                _ => Err(Error::GENERAL),
            }
        } else if (status.args() == Ok(edit::KEY_VALID)) && (state == Ok(State::Expire)) {
            Ok(State::Valid)
        } else if (status.args() == Ok(edit::CONFIRM_SAVE)) && (state == Ok(State::Quit)) {
            Ok(State::Save)
        } else {
            state.and(Err(Error::GENERAL))
        }
    }

    fn action(&self, state: Self::State, out: &mut dyn Write) -> Result<()> {
        use self::TestEditorState as State;

        match state {
            State::Fingerprint => out.write_all(b"fpr")?,
            State::Expire => out.write_all(b"expire")?,
            State::Valid => out.write_all(b"0")?,
            State::Uid => out.write_all(b"1")?,
            State::Primary => out.write_all(b"primary")?,
            State::Quit => write!(out, "{}", edit::QUIT)?,
            State::Save => write!(out, "{}", edit::YES)?,
            _ => return Err(Error::GENERAL),
        }
        Ok(())
    }
}

#[sealed_test(before = common::setup(), after = common::teardown())]
fn test_edit() {
    common::create_context().with_passphrase_provider(passphrase_cb, |ctx| {
        let key = ctx
            .find_keys(Some("Alpha"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        ctx.edit_key_with(&key, TestEditor, stdout()).unwrap();
    });
}
