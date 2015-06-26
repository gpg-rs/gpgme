use std::io::prelude::*;
use std::mem;

use Validity;
use error::{Error, Result};

use gpgme_sys as sys;

pub const QUIT: &'static str = "quit";
pub const YES: &'static str = "Y";
pub const NO: &'static str = "N";

enum_from_primitive! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub enum StatusCode {
        Unknown = -1,
        Eof = sys::GPGME_STATUS_EOF as isize,
        Enter = sys::GPGME_STATUS_ENTER as isize,
        Leave = sys::GPGME_STATUS_LEAVE as isize,
        Abort = sys::GPGME_STATUS_ABORT as isize,
        GoodSig = sys::GPGME_STATUS_GOODSIG as isize,
        BadSig = sys::GPGME_STATUS_BADSIG as isize,
        ErrSig = sys::GPGME_STATUS_ERRSIG as isize,
        BadArmor = sys::GPGME_STATUS_BADARMOR as isize,
        RsaOrIdea = sys::GPGME_STATUS_RSA_OR_IDEA as isize,
        KeyExpired = sys::GPGME_STATUS_KEYEXPIRED as isize,
        KeyRevoked = sys::GPGME_STATUS_KEYREVOKED as isize,
        TrustUndefined = sys::GPGME_STATUS_TRUST_UNDEFINED as isize,
        TrustNever = sys::GPGME_STATUS_TRUST_NEVER as isize,
        TrustMarginal = sys::GPGME_STATUS_TRUST_MARGINAL as isize,
        TrustFully = sys::GPGME_STATUS_TRUST_FULLY as isize,
        TrustUltimate = sys::GPGME_STATUS_TRUST_ULTIMATE as isize,
        ShmInfo = sys::GPGME_STATUS_SHM_INFO as isize,
        ShmGet = sys::GPGME_STATUS_SHM_GET as isize,
        ShmGetBool = sys::GPGME_STATUS_SHM_GET_BOOL as isize,
        ShmGetHidden = sys::GPGME_STATUS_SHM_GET_HIDDEN as isize,
        NeedPassphrase = sys::GPGME_STATUS_NEED_PASSPHRASE as isize,
        ValidSig = sys::GPGME_STATUS_VALIDSIG as isize,
        SigId = sys::GPGME_STATUS_SIG_ID as isize,
        EncTo = sys::GPGME_STATUS_ENC_TO as isize,
        NoData = sys::GPGME_STATUS_NODATA as isize,
        BadPassphrase = sys::GPGME_STATUS_BAD_PASSPHRASE as isize,
        NoPubkey = sys::GPGME_STATUS_NO_PUBKEY as isize,
        NoSeckey = sys::GPGME_STATUS_NO_SECKEY as isize,
        NeedPassphraseSym = sys::GPGME_STATUS_NEED_PASSPHRASE_SYM as isize,
        DecryptionFailed = sys::GPGME_STATUS_DECRYPTION_FAILED as isize,
        DecryptionOkay = sys::GPGME_STATUS_DECRYPTION_OKAY as isize,
        MissingPassphrase = sys::GPGME_STATUS_MISSING_PASSPHRASE as isize,
        GoodPassphrase = sys::GPGME_STATUS_GOOD_PASSPHRASE as isize,
        GoodMdc = sys::GPGME_STATUS_GOODMDC as isize,
        BadMdc = sys::GPGME_STATUS_BADMDC as isize,
        ErrMdc = sys::GPGME_STATUS_ERRMDC as isize,
        Imported = sys::GPGME_STATUS_IMPORTED as isize,
        ImportOk = sys::GPGME_STATUS_IMPORT_OK as isize,
        ImportProblem = sys::GPGME_STATUS_IMPORT_PROBLEM as isize,
        ImportRes = sys::GPGME_STATUS_IMPORT_RES as isize,
        FileStart = sys::GPGME_STATUS_FILE_START as isize,
        FileDone = sys::GPGME_STATUS_FILE_DONE as isize,
        FileError = sys::GPGME_STATUS_FILE_ERROR as isize,
        BeginDecryption = sys::GPGME_STATUS_BEGIN_DECRYPTION as isize,
        EndDecryption = sys::GPGME_STATUS_END_DECRYPTION as isize,
        BeginEncryption = sys::GPGME_STATUS_BEGIN_ENCRYPTION as isize,
        EndEncryption = sys::GPGME_STATUS_END_ENCRYPTION as isize,
        DeleteProblem = sys::GPGME_STATUS_DELETE_PROBLEM as isize,
        GetBool = sys::GPGME_STATUS_GET_BOOL as isize,
        GetLine = sys::GPGME_STATUS_GET_LINE as isize,
        GetHidden = sys::GPGME_STATUS_GET_HIDDEN as isize,
        GotIt = sys::GPGME_STATUS_GOT_IT as isize,
        Progress = sys::GPGME_STATUS_PROGRESS as isize,
        SigCreated = sys::GPGME_STATUS_SIG_CREATED as isize,
        SessionKey = sys::GPGME_STATUS_SESSION_KEY as isize,
        NotationName = sys::GPGME_STATUS_NOTATION_NAME as isize,
        NotationData = sys::GPGME_STATUS_NOTATION_DATA as isize,
        PolicyUrl = sys::GPGME_STATUS_POLICY_URL as isize,
        BeginStream = sys::GPGME_STATUS_BEGIN_STREAM as isize,
        EndStream = sys::GPGME_STATUS_END_STREAM as isize,
        KeyCreated = sys::GPGME_STATUS_KEY_CREATED as isize,
        UserIdHint = sys::GPGME_STATUS_USERID_HINT as isize,
        Unexpected = sys::GPGME_STATUS_UNEXPECTED as isize,
        InvRecp = sys::GPGME_STATUS_INV_RECP as isize,
        NoRecp = sys::GPGME_STATUS_NO_RECP as isize,
        AlreadySigned = sys::GPGME_STATUS_ALREADY_SIGNED as isize,
        SigExpired = sys::GPGME_STATUS_SIGEXPIRED as isize,
        ExpSig = sys::GPGME_STATUS_EXPSIG as isize,
        ExpKeySig = sys::GPGME_STATUS_EXPKEYSIG as isize,
        Truncated = sys::GPGME_STATUS_TRUNCATED as isize,
        Error = sys::GPGME_STATUS_ERROR as isize,
        NewSig = sys::GPGME_STATUS_NEWSIG as isize,
        RevKeySig = sys::GPGME_STATUS_REVKEYSIG as isize,
        SigSubpacket = sys::GPGME_STATUS_SIG_SUBPACKET as isize,
        NeedPassphrasePin = sys::GPGME_STATUS_NEED_PASSPHRASE_PIN as isize,
        ScOpFailure = sys::GPGME_STATUS_SC_OP_FAILURE as isize,
        ScOpSuccess = sys::GPGME_STATUS_SC_OP_SUCCESS as isize,
        CardCtrl = sys::GPGME_STATUS_CARDCTRL as isize,
        BackupKeyCreated = sys::GPGME_STATUS_BACKUP_KEY_CREATED as isize,
        PkaTrustBad = sys::GPGME_STATUS_PKA_TRUST_BAD as isize,
        PkaTrustGood = sys::GPGME_STATUS_PKA_TRUST_GOOD as isize,
        PlainText = sys::GPGME_STATUS_PLAINTEXT as isize,
        InvSgnr = sys::GPGME_STATUS_INV_SGNR as isize,
        NoSgnr = sys::GPGME_STATUS_NO_SGNR as isize,
        Success = sys::GPGME_STATUS_SUCCESS as isize,
        DecryptionInfo = sys::GPGME_STATUS_DECRYPTION_INFO as isize,
        PlaintextLength = sys::GPGME_STATUS_PLAINTEXT_LENGTH as isize,
        MountPoint = sys::GPGME_STATUS_MOUNTPOINT as isize,
        PinEntryLaunched = sys::GPGME_STATUS_PINENTRY_LAUNCHED as isize,
        Attribute = sys::GPGME_STATUS_ATTRIBUTE as isize,
        BeginSigning = sys::GPGME_STATUS_BEGIN_SIGNING as isize,
        KeyNotCreated = sys::GPGME_STATUS_KEY_NOT_CREATED as isize,
    }
}

impl StatusCode {
    pub fn can_ignore(&self) -> bool {
        match *self {
            StatusCode::Eof => true,
            StatusCode::GotIt => true,
            StatusCode::NeedPassphrase => true,
            StatusCode::NeedPassphraseSym => true,
            StatusCode::GoodPassphrase => true,
            StatusCode::BadPassphrase => true,
            StatusCode::MissingPassphrase => true,
            StatusCode::UserIdHint => true,
            StatusCode::SigExpired => true,
            StatusCode::KeyExpired => true,
            StatusCode::KeyCreated => true,
            StatusCode::AlreadySigned => true,
            StatusCode::Progress => true,
            _ => false,
        }
    }

    pub fn to_result(&self) -> Result<()> {
        match *self {
            StatusCode::MissingPassphrase => Err(Error::from_code(sys::GPG_ERR_NO_PASSPHRASE)),
            StatusCode::KeyExpired => Err(Error::from_code(sys::GPG_ERR_CERT_EXPIRED)),
            StatusCode::SigExpired => Err(Error::from_code(sys::GPG_ERR_SIG_EXPIRED)),
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

        let err_general = Err(Error::from_code(sys::GPG_ERR_GENERAL));
        match wrapper.state() {
            State::Start => {
                if (status == StatusCode::GetLine) && (args == KeyWord::Prompt) {
                    Ok(State::Command)
                } else  {
                    err_general
                }
            },
            State::Command => {
                if (status == StatusCode::GetLine) && (args == KeyWord::KeyName) {
                    Ok(State::Name)
                } else  {
                    err_general
                }
            },
            State::Name => {
                if (status == StatusCode::GetLine) && (args == KeyWord::KeyEmail) {
                    Ok(State::Email)
                } else if (status == StatusCode::GetLine) && (args == KeyWord::KeyName) {
                    Err(Error::from_code(sys::GPG_ERR_INV_NAME))
                } else  {
                    err_general
                }
            },
            State::Email => {
                if (status == StatusCode::GetLine) && (args == KeyWord::KeyComment) {
                    Ok(State::Comment)
                } else if (status == StatusCode::GetLine) && (args == KeyWord::KeyEmail) {
                    Err(Error::from_code(sys::GPG_ERR_INV_USER_ID))
                } else  {
                    err_general
                }
            },
            State::Comment => {
                if (status == StatusCode::GetLine) && (args == KeyWord::Prompt) {
                    Ok(State::Quit)
                } else if (status == StatusCode::GetLine) && (args == KeyWord::KeyComment) {
                    Err(Error::from_code(sys::GPG_ERR_INV_USER_ID))
                } else  {
                    err_general
                }
            },
            State::Quit => {
                if (status == StatusCode::GetBool) && (args == KeyWord::ConfirmSave) {
                    Ok(State::Save)
                } else {
                    err_general
                }
            },
            State::Error => {
                if (status == StatusCode::GetLine) && (args == KeyWord::Prompt) {
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
            _ => return Err(Error::from_code(sys::GPG_ERR_GENERAL)),
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

        let err_general = Err(Error::from_code(sys::GPG_ERR_GENERAL));
        match wrapper.state() {
            State::Start => {
                if (status == StatusCode::GetLine) && (args == KeyWord::Prompt) {
                    Ok(State::Command)
                } else {
                    err_general
                }
            },
            State::Command => {
                if (status == StatusCode::GetLine) &&
                   (args == KeyWord::Other("edit_ownertrust.value")) {
                    Ok(State::Value)
                } else {
                    err_general
                }
            },
            State::Value => {
                if (status == StatusCode::GetLine) && (args == KeyWord::Prompt) {
                    Ok(State::Quit)
                } else if (status == StatusCode::GetBool) &&
                          (args == KeyWord::Other("edit_ownertrust.set_ultimate.okay")) {
                    Ok(State::Confirm)
                } else {
                    err_general
                }
            },
            State::Quit => {
                if (status == StatusCode::GetBool) && (args == KeyWord::ConfirmSave) {
                    Ok(State::Confirm)
                } else {
                    err_general
                }
            },
            State::Confirm => {
                if (status == StatusCode::GetLine) && (args == KeyWord::Prompt) {
                    Ok(State::Quit)
                } else {
                    err_general
                }
            },
            State::Error => {
                if (status == StatusCode::GetLine) && (args == KeyWord::Prompt) {
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
            State::Value => try!(write!(out, "{}", self.trust as u32)),
            State::Quit => try!(out.write_all(QUIT.as_bytes())),
            State::Confirm => try!(out.write_all(YES.as_bytes())),
            _ => return Err(Error::from_code(sys::GPG_ERR_GENERAL)),
        }
        Ok(())
    }
}
