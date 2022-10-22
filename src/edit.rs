#![allow(non_camel_case_types, deprecated)]
use std::{fmt, io::prelude::*, panic::UnwindSafe};

use ffi;

use crate::{Error, Result};

pub use crate::{EditInteractionStatus, EditInteractor};

ffi_enum_wrapper! {
    pub enum StatusCode: ffi::gpgme_status_code_t {
        Eof = ffi::GPGME_STATUS_EOF,
        Enter = ffi::GPGME_STATUS_ENTER,
        Leave = ffi::GPGME_STATUS_LEAVE,
        Abort = ffi::GPGME_STATUS_ABORT,
        GoodSig = ffi::GPGME_STATUS_GOODSIG,
        BadSig = ffi::GPGME_STATUS_BADSIG,
        ErrSig = ffi::GPGME_STATUS_ERRSIG,
        BadArmor = ffi::GPGME_STATUS_BADARMOR,
        RsaOrIdea = ffi::GPGME_STATUS_RSA_OR_IDEA,
        KeyExpired = ffi::GPGME_STATUS_KEYEXPIRED,
        KeyRevoked = ffi::GPGME_STATUS_KEYREVOKED,
        TrustUndefined = ffi::GPGME_STATUS_TRUST_UNDEFINED,
        TrustNever = ffi::GPGME_STATUS_TRUST_NEVER,
        TrustMarginal = ffi::GPGME_STATUS_TRUST_MARGINAL,
        TrustFully = ffi::GPGME_STATUS_TRUST_FULLY,
        TrustUltimate = ffi::GPGME_STATUS_TRUST_ULTIMATE,
        ShmInfo = ffi::GPGME_STATUS_SHM_INFO,
        ShmGet = ffi::GPGME_STATUS_SHM_GET,
        ShmGetBool = ffi::GPGME_STATUS_SHM_GET_BOOL,
        ShmGetHidden = ffi::GPGME_STATUS_SHM_GET_HIDDEN,
        NeedPassphrase = ffi::GPGME_STATUS_NEED_PASSPHRASE,
        ValidSig = ffi::GPGME_STATUS_VALIDSIG,
        SigId = ffi::GPGME_STATUS_SIG_ID,
        EncTo = ffi::GPGME_STATUS_ENC_TO,
        NoData = ffi::GPGME_STATUS_NODATA,
        BadPassphrase = ffi::GPGME_STATUS_BAD_PASSPHRASE,
        NoPubKey = ffi::GPGME_STATUS_NO_PUBKEY,
        NoSecKey = ffi::GPGME_STATUS_NO_SECKEY,
        NeedPassphraseSym = ffi::GPGME_STATUS_NEED_PASSPHRASE_SYM,
        DecryptionFailed = ffi::GPGME_STATUS_DECRYPTION_FAILED,
        DecryptionOkay = ffi::GPGME_STATUS_DECRYPTION_OKAY,
        MissingPassphrase = ffi::GPGME_STATUS_MISSING_PASSPHRASE,
        GoodPassphrase = ffi::GPGME_STATUS_GOOD_PASSPHRASE,
        GoodMdc = ffi::GPGME_STATUS_GOODMDC,
        BadMdc = ffi::GPGME_STATUS_BADMDC,
        ErrMdc = ffi::GPGME_STATUS_ERRMDC,
        Imported = ffi::GPGME_STATUS_IMPORTED,
        ImportOk = ffi::GPGME_STATUS_IMPORT_OK,
        ImportProblem = ffi::GPGME_STATUS_IMPORT_PROBLEM,
        ImportRes = ffi::GPGME_STATUS_IMPORT_RES,
        FileStart = ffi::GPGME_STATUS_FILE_START,
        FileDone = ffi::GPGME_STATUS_FILE_DONE,
        FileError = ffi::GPGME_STATUS_FILE_ERROR,
        BeginDecryption = ffi::GPGME_STATUS_BEGIN_DECRYPTION,
        EndDecryption = ffi::GPGME_STATUS_END_DECRYPTION,
        BeginEncryption = ffi::GPGME_STATUS_BEGIN_ENCRYPTION,
        EndEncryption = ffi::GPGME_STATUS_END_ENCRYPTION,
        DeleteProblem = ffi::GPGME_STATUS_DELETE_PROBLEM,
        GetBool = ffi::GPGME_STATUS_GET_BOOL,
        GetLine = ffi::GPGME_STATUS_GET_LINE,
        GetHidden = ffi::GPGME_STATUS_GET_HIDDEN,
        GotIt = ffi::GPGME_STATUS_GOT_IT,
        Progress = ffi::GPGME_STATUS_PROGRESS,
        SigCreated = ffi::GPGME_STATUS_SIG_CREATED,
        SessionKey = ffi::GPGME_STATUS_SESSION_KEY,
        NotationName = ffi::GPGME_STATUS_NOTATION_NAME,
        NotationData = ffi::GPGME_STATUS_NOTATION_DATA,
        PolicyUrl = ffi::GPGME_STATUS_POLICY_URL,
        BeginStream = ffi::GPGME_STATUS_BEGIN_STREAM,
        EndStream = ffi::GPGME_STATUS_END_STREAM,
        KeyCreated = ffi::GPGME_STATUS_KEY_CREATED,
        UserIdHint = ffi::GPGME_STATUS_USERID_HINT,
        Unexpected = ffi::GPGME_STATUS_UNEXPECTED,
        InvRecp = ffi::GPGME_STATUS_INV_RECP,
        NoRecp = ffi::GPGME_STATUS_NO_RECP,
        AlreadySigned = ffi::GPGME_STATUS_ALREADY_SIGNED,
        SigExpired = ffi::GPGME_STATUS_SIGEXPIRED,
        ExpSig = ffi::GPGME_STATUS_EXPSIG,
        ExpKeySig = ffi::GPGME_STATUS_EXPKEYSIG,
        Truncated = ffi::GPGME_STATUS_TRUNCATED,
        Error = ffi::GPGME_STATUS_ERROR,
        NewSig = ffi::GPGME_STATUS_NEWSIG,
        RevKeySig = ffi::GPGME_STATUS_REVKEYSIG,
        SigSubpacket = ffi::GPGME_STATUS_SIG_SUBPACKET,
        NeedPassphrasePin = ffi::GPGME_STATUS_NEED_PASSPHRASE_PIN,
        ScOpFailure = ffi::GPGME_STATUS_SC_OP_FAILURE,
        ScOpSuccess = ffi::GPGME_STATUS_SC_OP_SUCCESS,
        CardCtrl = ffi::GPGME_STATUS_CARDCTRL,
        BackupKeyCreated = ffi::GPGME_STATUS_BACKUP_KEY_CREATED,
        PkaTrustBad = ffi::GPGME_STATUS_PKA_TRUST_BAD,
        PkaTrustGood = ffi::GPGME_STATUS_PKA_TRUST_GOOD,
        Plaintext = ffi::GPGME_STATUS_PLAINTEXT,
        InvSgnr = ffi::GPGME_STATUS_INV_SGNR,
        NoSgnr = ffi::GPGME_STATUS_NO_SGNR,
        Success = ffi::GPGME_STATUS_SUCCESS,
        DecryptionInfo = ffi::GPGME_STATUS_DECRYPTION_INFO,
        PlaintextLength = ffi::GPGME_STATUS_PLAINTEXT_LENGTH,
        Mountpoint = ffi::GPGME_STATUS_MOUNTPOINT,
        PinentryLaunched = ffi::GPGME_STATUS_PINENTRY_LAUNCHED,
        Attribute = ffi::GPGME_STATUS_ATTRIBUTE,
        BeginSigning = ffi::GPGME_STATUS_BEGIN_SIGNING,
        KeyNotCreated = ffi::GPGME_STATUS_KEY_NOT_CREATED,
        InquireMaxLen = ffi::GPGME_STATUS_INQUIRE_MAXLEN,
        Failure = ffi::GPGME_STATUS_FAILURE,
        KeyConsidered = ffi::GPGME_STATUS_KEY_CONSIDERED,
        TofuUser = ffi::GPGME_STATUS_TOFU_USER,
        TofuStats = ffi::GPGME_STATUS_TOFU_STATS,
        TofuStatsLong = ffi::GPGME_STATUS_TOFU_STATS_LONG,
        NotationFlags = ffi::GPGME_STATUS_NOTATION_FLAGS,
    }
}

impl StatusCode {
    pub fn into_result(self) -> Result<()> {
        match self {
            StatusCode::MissingPassphrase => Err(Error::NO_PASSPHRASE),
            StatusCode::AlreadySigned => Err(Error::USER_1),
            StatusCode::SigExpired => Err(Error::SIG_EXPIRED),
            _ => Ok(()),
        }
    }
}

// Actions
pub const QUIT: &str = "quit";
pub const SAVE: &str = "save";
pub const YES: &str = "Y";
pub const NO: &str = "N";

// Keywords
pub const PROMPT: &str = "keyedit.prompt";
pub const CONFIRM_SAVE: &str = "keyedit.save.okay";
pub const CONFIRM_CANCEL: &str = "keyedit.cancel.okay";
pub const CONFIRM_KEY_VALID: &str = "keygen.valid.okay";
pub const CONFIRM_CREATE_KEY: &str = "keygen.sub.okay";
pub const KEY_NAME: &str = "keygen.name";
pub const KEY_EMAIL: &str = "keygen.email";
pub const KEY_COMMENT: &str = "keygen.comment";
pub const KEY_VALID: &str = "keygen.valid";
pub const KEY_FLAGS: &str = "keygen.flags";
pub const KEY_SIZE: &str = "keygen.size";
pub const KEY_ALGORITHM: &str = "keygen.algo";
pub const KEY_UID_COMMAND: &str = "keygen.userid.cmd";
pub const KEY_CURVE: &str = "keygen.curve";

pub trait Editor: UnwindSafe + Send {
    type State: fmt::Debug + Default + Eq + Copy + UnwindSafe + Send;

    fn next_state(
        state: Result<Self::State>,
        status: EditInteractionStatus<'_>,
        need_response: bool,
    ) -> Result<Self::State>;
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
            editor,
            state: Ok(E::State::default()),
        }
    }
}

impl<E: Editor> EditInteractor for EditorWrapper<E> {
    fn interact<W: Write>(
        &mut self,
        status: EditInteractionStatus<'_>,
        out: Option<W>,
    ) -> Result<()> {
        let old_state = self.state;
        self.state = status
            .code
            .into_result()
            .and_then(|_| E::next_state(self.state, status, out.is_some()))
            .and_then(|state| {
                if old_state == Ok(state) {
                    return Ok(state);
                }

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
