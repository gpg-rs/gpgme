use std::io::prelude::*;
use std::mem;

use ffi;

use Validity;
use error::{self, Error, Result};

pub const QUIT: &'static str = "quit";
pub const YES: &'static str = "Y";
pub const NO: &'static str = "N";

ffi_enum_wrapper! {
    pub enum StatusCode: ffi::gpgme_status_code_t {
        STATUS_EOF = ffi::GPGME_STATUS_EOF,
        STATUS_ENTER = ffi::GPGME_STATUS_ENTER,
        STATUS_LEAVE = ffi::GPGME_STATUS_LEAVE,
        STATUS_ABORT = ffi::GPGME_STATUS_ABORT,
        STATUS_GOODSIG = ffi::GPGME_STATUS_GOODSIG,
        STATUS_BADSIG = ffi::GPGME_STATUS_BADSIG,
        STATUS_ERRSIG = ffi::GPGME_STATUS_ERRSIG,
        STATUS_BADARMOR = ffi::GPGME_STATUS_BADARMOR,
        STATUS_RSA_OR_IDEA = ffi::GPGME_STATUS_RSA_OR_IDEA,
        STATUS_KEYEXPIRED = ffi::GPGME_STATUS_KEYEXPIRED,
        STATUS_KEYREVOKED = ffi::GPGME_STATUS_KEYREVOKED,
        STATUS_TRUST_UNDEFINED = ffi::GPGME_STATUS_TRUST_UNDEFINED,
        STATUS_TRUST_NEVER = ffi::GPGME_STATUS_TRUST_NEVER,
        STATUS_TRUST_MARGINAL = ffi::GPGME_STATUS_TRUST_MARGINAL,
        STATUS_TRUST_FULLY = ffi::GPGME_STATUS_TRUST_FULLY,
        STATUS_TRUST_ULTIMATE = ffi::GPGME_STATUS_TRUST_ULTIMATE,
        STATUS_SHM_INFO = ffi::GPGME_STATUS_SHM_INFO,
        STATUS_SHM_GET = ffi::GPGME_STATUS_SHM_GET,
        STATUS_SHM_GET_BOOL = ffi::GPGME_STATUS_SHM_GET_BOOL,
        STATUS_SHM_GET_HIDDEN = ffi::GPGME_STATUS_SHM_GET_HIDDEN,
        STATUS_NEED_PASSPHRASE = ffi::GPGME_STATUS_NEED_PASSPHRASE,
        STATUS_VALIDSIG = ffi::GPGME_STATUS_VALIDSIG,
        STATUS_SIG_ID = ffi::GPGME_STATUS_SIG_ID,
        STATUS_ENC_TO = ffi::GPGME_STATUS_ENC_TO,
        STATUS_NODATA = ffi::GPGME_STATUS_NODATA,
        STATUS_BAD_PASSPHRASE = ffi::GPGME_STATUS_BAD_PASSPHRASE,
        STATUS_NO_PUBKEY = ffi::GPGME_STATUS_NO_PUBKEY,
        STATUS_NO_SECKEY = ffi::GPGME_STATUS_NO_SECKEY,
        STATUS_NEED_PASSPHRASE_SYM = ffi::GPGME_STATUS_NEED_PASSPHRASE_SYM,
        STATUS_DECRYPTION_FAILED = ffi::GPGME_STATUS_DECRYPTION_FAILED,
        STATUS_DECRYPTION_OKAY = ffi::GPGME_STATUS_DECRYPTION_OKAY,
        STATUS_MISSING_PASSPHRASE = ffi::GPGME_STATUS_MISSING_PASSPHRASE,
        STATUS_GOOD_PASSPHRASE = ffi::GPGME_STATUS_GOOD_PASSPHRASE,
        STATUS_GOODMDC = ffi::GPGME_STATUS_GOODMDC,
        STATUS_BADMDC = ffi::GPGME_STATUS_BADMDC,
        STATUS_ERRMDC = ffi::GPGME_STATUS_ERRMDC,
        STATUS_IMPORTED = ffi::GPGME_STATUS_IMPORTED,
        STATUS_IMPORT_OK = ffi::GPGME_STATUS_IMPORT_OK,
        STATUS_IMPORT_PROBLEM = ffi::GPGME_STATUS_IMPORT_PROBLEM,
        STATUS_IMPORT_RES = ffi::GPGME_STATUS_IMPORT_RES,
        STATUS_FILE_START = ffi::GPGME_STATUS_FILE_START,
        STATUS_FILE_DONE = ffi::GPGME_STATUS_FILE_DONE,
        STATUS_FILE_ERROR = ffi::GPGME_STATUS_FILE_ERROR,
        STATUS_BEGIN_DECRYPTION = ffi::GPGME_STATUS_BEGIN_DECRYPTION,
        STATUS_END_DECRYPTION = ffi::GPGME_STATUS_END_DECRYPTION,
        STATUS_BEGIN_ENCRYPTION = ffi::GPGME_STATUS_BEGIN_ENCRYPTION,
        STATUS_END_ENCRYPTION = ffi::GPGME_STATUS_END_ENCRYPTION,
        STATUS_DELETE_PROBLEM = ffi::GPGME_STATUS_DELETE_PROBLEM,
        STATUS_GET_BOOL = ffi::GPGME_STATUS_GET_BOOL,
        STATUS_GET_LINE = ffi::GPGME_STATUS_GET_LINE,
        STATUS_GET_HIDDEN = ffi::GPGME_STATUS_GET_HIDDEN,
        STATUS_GOT_IT = ffi::GPGME_STATUS_GOT_IT,
        STATUS_PROGRESS = ffi::GPGME_STATUS_PROGRESS,
        STATUS_SIG_CREATED = ffi::GPGME_STATUS_SIG_CREATED,
        STATUS_SESSION_KEY = ffi::GPGME_STATUS_SESSION_KEY,
        STATUS_NOTATION_NAME = ffi::GPGME_STATUS_NOTATION_NAME,
        STATUS_NOTATION_DATA = ffi::GPGME_STATUS_NOTATION_DATA,
        STATUS_POLICY_URL = ffi::GPGME_STATUS_POLICY_URL,
        STATUS_BEGIN_STREAM = ffi::GPGME_STATUS_BEGIN_STREAM,
        STATUS_END_STREAM = ffi::GPGME_STATUS_END_STREAM,
        STATUS_KEY_CREATED = ffi::GPGME_STATUS_KEY_CREATED,
        STATUS_USERID_HINT = ffi::GPGME_STATUS_USERID_HINT,
        STATUS_UNEXPECTED = ffi::GPGME_STATUS_UNEXPECTED,
        STATUS_INV_RECP = ffi::GPGME_STATUS_INV_RECP,
        STATUS_NO_RECP = ffi::GPGME_STATUS_NO_RECP,
        STATUS_ALREADY_SIGNED = ffi::GPGME_STATUS_ALREADY_SIGNED,
        STATUS_SIGEXPIRED = ffi::GPGME_STATUS_SIGEXPIRED,
        STATUS_EXPSIG = ffi::GPGME_STATUS_EXPSIG,
        STATUS_EXPKEYSIG = ffi::GPGME_STATUS_EXPKEYSIG,
        STATUS_TRUNCATED = ffi::GPGME_STATUS_TRUNCATED,
        STATUS_ERROR = ffi::GPGME_STATUS_ERROR,
        STATUS_NEWSIG = ffi::GPGME_STATUS_NEWSIG,
        STATUS_REVKEYSIG = ffi::GPGME_STATUS_REVKEYSIG,
        STATUS_SIG_SUBPACKET = ffi::GPGME_STATUS_SIG_SUBPACKET,
        STATUS_NEED_PASSPHRASE_PIN = ffi::GPGME_STATUS_NEED_PASSPHRASE_PIN,
        STATUS_SC_OP_FAILURE = ffi::GPGME_STATUS_SC_OP_FAILURE,
        STATUS_SC_OP_SUCCESS = ffi::GPGME_STATUS_SC_OP_SUCCESS,
        STATUS_CARDCTRL = ffi::GPGME_STATUS_CARDCTRL,
        STATUS_BACKUP_KEY_CREATED = ffi::GPGME_STATUS_BACKUP_KEY_CREATED,
        STATUS_PKA_TRUST_BAD = ffi::GPGME_STATUS_PKA_TRUST_BAD,
        STATUS_PKA_TRUST_GOOD = ffi::GPGME_STATUS_PKA_TRUST_GOOD,
        STATUS_PLAINTEXT = ffi::GPGME_STATUS_PLAINTEXT,
        STATUS_INV_SGNR = ffi::GPGME_STATUS_INV_SGNR,
        STATUS_NO_SGNR = ffi::GPGME_STATUS_NO_SGNR,
        STATUS_SUCCESS = ffi::GPGME_STATUS_SUCCESS,
        STATUS_DECRYPTION_INFO = ffi::GPGME_STATUS_DECRYPTION_INFO,
        STATUS_PLAINTEXT_LENGTH = ffi::GPGME_STATUS_PLAINTEXT_LENGTH,
        STATUS_MOUNTPOINT = ffi::GPGME_STATUS_MOUNTPOINT,
        STATUS_PINENTRY_LAUNCHED = ffi::GPGME_STATUS_PINENTRY_LAUNCHED,
        STATUS_ATTRIBUTE = ffi::GPGME_STATUS_ATTRIBUTE,
        STATUS_BEGIN_SIGNING = ffi::GPGME_STATUS_BEGIN_SIGNING,
        STATUS_KEY_NOT_CREATED = ffi::GPGME_STATUS_KEY_NOT_CREATED,
    }
}

impl StatusCode {
    pub fn can_ignore(&self) -> bool {
        match *self {
            STATUS_EOF => true,
            STATUS_GOT_IT => true,
            STATUS_NEED_PASSPHRASE => true,
            STATUS_NEED_PASSPHRASE_SYM => true,
            STATUS_GOOD_PASSPHRASE => true,
            STATUS_BAD_PASSPHRASE => true,
            STATUS_MISSING_PASSPHRASE => true,
            STATUS_USERID_HINT => true,
            STATUS_SIGEXPIRED => true,
            STATUS_KEYEXPIRED => true,
            STATUS_KEY_CREATED => true,
            STATUS_ALREADY_SIGNED => true,
            STATUS_PROGRESS => true,
            _ => false,
        }
    }

    pub fn to_result(&self) -> Result<()> {
        match *self {
            STATUS_MISSING_PASSPHRASE => Err(Error::from_code(error::GPG_ERR_NO_PASSPHRASE)),
            STATUS_KEYEXPIRED => Err(Error::from_code(error::GPG_ERR_CERT_EXPIRED)),
            STATUS_SIGEXPIRED => Err(Error::from_code(error::GPG_ERR_SIG_EXPIRED)),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum KeyWord<'a> {
    Prompt,
    ConfirmSave,
    ConfirmCancel,
    ConfirmKeyValid,
    ConfirmCreateKey,
    KeyName,
    KeyEmail,
    KeyComment,
    KeyValid,
    KeyFlags,
    KeySize,
    KeyAlgorithm,
    KeyCurve,
    KeyUidPrompt,
    Other(&'a str),
}

impl<'a> From<&'a str> for KeyWord<'a> {
    fn from(word: &'a str) -> KeyWord<'a> {
        match word {
            "keyedit.prompt" => KeyWord::Prompt,
            "keyedit.save.okay" => KeyWord::ConfirmSave,
            "keyedit.cancel.okay" => KeyWord::ConfirmCancel,
            "keygen.valid.okay" => KeyWord::ConfirmKeyValid,
            "keygen.name" => KeyWord::KeyName,
            "keygen.email" => KeyWord::KeyEmail,
            "keygen.comment" => KeyWord::KeyComment,
            "keygen.valid" => KeyWord::KeyValid,
            "keygen.flags" => KeyWord::KeyFlags,
            "keygen.size" => KeyWord::KeySize,
            "keygen.algo" => KeyWord::KeyAlgorithm,
            "keygen.userid.cmd" => KeyWord::KeyUidPrompt,
            "keygen.curve" => KeyWord::KeyCurve,
            "keygen.sub.okay" => KeyWord::ConfirmCreateKey,
            _ => KeyWord::Other(word),
        }
    }
}

pub trait EditorState: Copy + Eq {
    fn start() -> Self;
    fn error() -> Self;
}

pub trait Editor: 'static + Send {
    type State: EditorState;

    fn next_state<'a>(wrapper: &EditorWrapper<Self>, status: StatusCode,
                      args: KeyWord<'a>) -> Result<Self::State>;
    fn action(&self, state: Self::State, out: &mut Write) -> Result<()>;
}

pub struct EditorWrapper<E: Editor> {
    editor: E,
    state: E::State,
    error: Error,
}

impl<E: Editor> EditorWrapper<E> {
    pub fn new(editor: E) -> EditorWrapper<E> {
        EditorWrapper {
            editor: editor,
            state: E::State::start(),
            error: Error::new(0),
        }
    }

    pub fn state(&self) -> E::State {
        self.state
    }

    pub fn last_error(&self) -> Error {
        self.error
    }

    pub fn callback<W: Write>(&mut self, status: StatusCode, args: Option<&str>,
                              output: &mut W) -> Result<()> {
        let result = status.to_result().and_then(|_| {
            E::next_state(self, status, KeyWord::from(args.unwrap_or("")))
        }).and_then(|state| {
            if mem::replace(&mut self.state, state) != state {
                self.editor.action(state, output).and_then(|_| {
                    output.write_all(b"\n").map_err(|err| err.into())
                })
            } else {
                Ok(())
            }
        });
        if let Some(err) = result.err() {
            self.state = E::State::error();
            self.error = err;
        }
        result
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AddUserIdState {
    Start,
    Command,
    Name,
    Email,
    Comment,
    Quit,
    Save,
    Error,
}

impl EditorState for AddUserIdState {
    fn start() -> Self {
        AddUserIdState::Start
    }

    fn error() -> Self {
        AddUserIdState::Error
    }
}

pub struct AddUserIdEditor {
    name: String,
    email: String,
    comment: String,
}

impl AddUserIdEditor {
    pub fn new(name: String, email: String, comment: String) -> AddUserIdEditor {
        AddUserIdEditor {
            name: name,
            email: email,
            comment: comment,
        }
    }
}

impl Editor for AddUserIdEditor {
    type State = AddUserIdState;

    fn next_state<'a>(wrapper: &EditorWrapper<Self>, status: StatusCode,
                      args: KeyWord<'a>) -> Result<Self::State> {
        use self::AddUserIdState as State;

        if status.can_ignore() {
            return Ok(wrapper.state());
        }

        let err_general = Err(Error::from_code(error::GPG_ERR_GENERAL));
        match wrapper.state() {
            State::Start => {
                if (status == STATUS_GET_LINE) && (args == KeyWord::Prompt) {
                    Ok(State::Command)
                } else  {
                    err_general
                }
            },
            State::Command => {
                if (status == STATUS_GET_LINE) && (args == KeyWord::KeyName) {
                    Ok(State::Name)
                } else  {
                    err_general
                }
            },
            State::Name => {
                if (status == STATUS_GET_LINE) && (args == KeyWord::KeyEmail) {
                    Ok(State::Email)
                } else if (status == STATUS_GET_LINE) && (args == KeyWord::KeyName) {
                    Err(Error::from_code(error::GPG_ERR_INV_NAME))
                } else  {
                    err_general
                }
            },
            State::Email => {
                if (status == STATUS_GET_LINE) && (args == KeyWord::KeyComment) {
                    Ok(State::Comment)
                } else if (status == STATUS_GET_LINE) && (args == KeyWord::KeyEmail) {
                    Err(Error::from_code(error::GPG_ERR_INV_USER_ID))
                } else  {
                    err_general
                }
            },
            State::Comment => {
                if (status == STATUS_GET_LINE) && (args == KeyWord::Prompt) {
                    Ok(State::Quit)
                } else if (status == STATUS_GET_LINE) && (args == KeyWord::KeyComment) {
                    Err(Error::from_code(error::GPG_ERR_INV_USER_ID))
                } else  {
                    err_general
                }
            },
            State::Quit => {
                if (status == STATUS_GET_BOOL) && (args == KeyWord::ConfirmSave) {
                    Ok(State::Save)
                } else {
                    err_general
                }
            },
            State::Error => {
                if (status == STATUS_GET_LINE) && (args == KeyWord::Prompt) {
                    Ok(State::Quit)
                } else {
                    Err(wrapper.last_error())
                }
            },
            _ => err_general,
        }
    }

    fn action(&self, state: Self::State, out: &mut Write) -> Result<()> {
        use self::AddUserIdState as State;

        match state {
            State::Command => try!(out.write_all(b"adduid")),
            State::Name => try!(out.write_all(self.name.as_bytes())),
            State::Email => try!(out.write_all(self.email.as_bytes())),
            State::Comment => try!(out.write_all(self.comment.as_bytes())),
            State::Quit => try!(out.write_all(QUIT.as_bytes())),
            State::Save => try!(out.write_all(YES.as_bytes())),
            _ => return Err(Error::from_code(error::GPG_ERR_GENERAL)),
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ChangeTrustState {
    Start,
    Command,
    Value,
    Quit,
    Confirm,
    Error,
}

impl EditorState for ChangeTrustState {
    fn start() -> Self {
        ChangeTrustState::Start
    }

    fn error() -> Self {
        ChangeTrustState::Error
    }
}

pub struct ChangeTrustEditor {
    trust: Validity,
}

impl ChangeTrustEditor {
    pub fn new(trust: Validity) -> ChangeTrustEditor {
        ChangeTrustEditor {
            trust: trust
        }
    }
}

impl Editor for ChangeTrustEditor {
    type State = ChangeTrustState;

    fn next_state<'a>(wrapper: &EditorWrapper<Self>, status: StatusCode,
                      args: KeyWord<'a>) -> Result<Self::State> {
        use self::ChangeTrustState as State;

        if status.can_ignore() {
            return Ok(wrapper.state());
        }

        let err_general = Err(Error::from_code(error::GPG_ERR_GENERAL));
        match wrapper.state() {
            State::Start => {
                if (status == STATUS_GET_LINE) && (args == KeyWord::Prompt) {
                    Ok(State::Command)
                } else {
                    err_general
                }
            },
            State::Command => {
                if (status == STATUS_GET_LINE) &&
                   (args == KeyWord::Other("edit_ownertrust.value")) {
                    Ok(State::Value)
                } else {
                    err_general
                }
            },
            State::Value => {
                if (status == STATUS_GET_LINE) && (args == KeyWord::Prompt) {
                    Ok(State::Quit)
                } else if (status == STATUS_GET_BOOL) &&
                          (args == KeyWord::Other("edit_ownertrust.set_ultimate.okay")) {
                    Ok(State::Confirm)
                } else {
                    err_general
                }
            },
            State::Quit => {
                if (status == STATUS_GET_BOOL) && (args == KeyWord::ConfirmSave) {
                    Ok(State::Confirm)
                } else {
                    err_general
                }
            },
            State::Confirm => {
                if (status == STATUS_GET_LINE) && (args == KeyWord::Prompt) {
                    Ok(State::Quit)
                } else {
                    err_general
                }
            },
            State::Error => {
                if (status == STATUS_GET_LINE) && (args == KeyWord::Prompt) {
                    Ok(State::Quit)
                } else {
                    Err(wrapper.last_error())
                }
            },
        }
    }

    fn action(&self, state: Self::State, out: &mut Write) -> Result<()> {
        use self::ChangeTrustState as State;

        match state {
            State::Command => try!(out.write_all(b"trust")),
            State::Value => try!(write!(out, "{}", self.trust.raw())),
            State::Quit => try!(out.write_all(QUIT.as_bytes())),
            State::Confirm => try!(out.write_all(YES.as_bytes())),
            _ => return Err(Error::from_code(error::GPG_ERR_GENERAL)),
        }
        Ok(())
    }
}
