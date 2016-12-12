#![allow(non_camel_case_types)]
use std::fmt;
use std::io::prelude::*;

use ffi;

use {Error, Result};
pub use {EditHandler, EditStatus};

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
        STATUS_INQUIRE_MAXLEN = ffi::GPGME_STATUS_INQUIRE_MAXLEN,
        STATUS_FAILURE = ffi::GPGME_STATUS_FAILURE,
        STATUS_KEY_CONSIDERED = ffi::GPGME_STATUS_KEY_CONSIDERED,
        STATUS_TOFU_USER = ffi::GPGME_STATUS_TOFU_USER,
        STATUS_TOFU_STATS = ffi::GPGME_STATUS_TOFU_STATS,
        STATUS_TOFU_STATS_LONG = ffi::GPGME_STATUS_TOFU_STATS_LONG,
        STATUS_NOTATION_FLAGS = ffi::GPGME_STATUS_NOTATION_FLAGS,
    }
}

impl StatusCode {
    pub fn is_command(&self) -> bool {
        match *self {
            StatusCode::STATUS_GET_BOOL |
            StatusCode::STATUS_GET_LINE |
            StatusCode::STATUS_GET_HIDDEN => true,
            _ => false,
        }
    }
}

// Actions
pub const QUIT: &'static str = "quit";
pub const SAVE: &'static str = "save";
pub const YES: &'static str = "Y";
pub const NO: &'static str = "N";

// Keywords
pub const PROMPT: &'static str = "keyedit.prompt";
pub const CONFIRM_SAVE: &'static str = "keyedit.save.okay";
pub const CONFIRM_CANCEL: &'static str = "keyedit.cancel.okay";
pub const CONFIRM_KEY_VALID: &'static str = "keygen.valid.okay";
pub const CONFIRM_CREATE_KEY: &'static str = "keygen.sub.okay";
pub const KEY_NAME: &'static str = "keygen.name";
pub const KEY_EMAIL: &'static str = "keygen.email";
pub const KEY_COMMENT: &'static str = "keygen.comment";
pub const KEY_VALID: &'static str = "keygen.valid";
pub const KEY_FLAGS: &'static str = "keygen.flags";
pub const KEY_SIZE: &'static str = "keygen.size";
pub const KEY_ALGORITHM: &'static str = "keygen.algo";
pub const KEY_UID_COMMAND: &'static str = "keygen.userid.cmd";
pub const KEY_CURVE: &'static str = "keygen.curve";

pub trait Editor: 'static + Send {
    type State: 'static + Send + Copy + Eq + fmt::Debug;

    fn start() -> Self::State;

    fn next_state(state: Result<Self::State>, status: EditStatus) -> Result<Self::State>;
    fn action<W: Write>(&self, state: Self::State, out: W) -> Result<()>;
}

#[derive(Debug)]
pub struct EditorWrapper<E: Editor> {
    editor: E,
    state: Result<E::State>,
}

impl<E: Editor> EditorWrapper<E> {
    pub fn new(editor: E) -> EditorWrapper<E> {
        EditorWrapper {
            editor: editor,
            state: Ok(E::start()),
        }
    }
}

impl<E: Editor> EditHandler for EditorWrapper<E> {
    fn handle<W: Write>(&mut self, status: EditStatus, out: Option<W>) -> Result<()> {
        self.state = E::next_state(self.state, status).and_then(|state| {
            out.map_or(Ok(()), |mut out| {
                    self.editor
                        .action(state, &mut out)
                        .and_then(|_| out.write_all(b"\n").map_err(Error::from))
                })
                .and(Ok(state))
        });
        self.state.and(Ok(()))
    }
}
