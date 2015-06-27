extern crate libc;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate enum_primitive;
#[macro_use]
extern crate lazy_static;
extern crate gpgme_sys;

use std::ffi::CString;
use std::fmt;
use std::mem;
use std::ptr;
use std::sync::{Arc, RwLock};

use gpgme_sys as sys;

pub use self::error::{Result, Error, ErrorCode};
pub use self::engine::{EngineInfo, EngineInfoGuard};
pub use self::context::{Context, Keys, TrustItems, PassphraseCallback, ProgressCallback};
pub use self::data::{DataEncoding, DataType, Data, WrappedError};
pub use self::keys::{Validity, KeyAlgorithm, HashAlgorithm, Key, KeySignature, SubKey, UserId};
pub use self::trust::TrustItem;
pub use self::notation::{SignatureNotationFlags, SignatureNotation, NOTATION_HUMAN_READABLE,
    NOTATION_CRITICAL};

#[macro_use]
mod utils;
pub mod error;
mod engine;
mod context;
mod data;
mod keys;
mod trust;
mod notation;
pub mod ops;

/// Constants for use with `Token::get_dir_info`.
pub mod info {
    pub const HOME_DIR: &'static str = "homedir";
    pub const AGENT_SOCKET: &'static str = "agent-socket";
    pub const UISERVER_SOCKET: &'static str = "uiserver-socket";
    pub const GPGCONF_NAME: &'static str = "gpgconf-name";
    pub const GPG_NAME: &'static str = "gpg-name";
    pub const GPGSM_NAME: &'static str = "gpgsm-name";
    pub const G13_NAME: &'static str = "g13-name";
}

enum_from_primitive! {
    /// A list of cryptographic protocols that may be supported by the library.
    ///
    /// Each protocol is implemented by an engine that the library communicates with
    /// to perform various operations.
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub enum Protocol {
        OpenPgp = sys::GPGME_PROTOCOL_OpenPGP as isize,
        Cms = sys::GPGME_PROTOCOL_CMS as isize,
        GpgConf = sys::GPGME_PROTOCOL_GPGCONF as isize,
        Assuan = sys::GPGME_PROTOCOL_ASSUAN as isize,
        G13 = sys::GPGME_PROTOCOL_G13 as isize,
        UiServer = sys::GPGME_PROTOCOL_UISERVER as isize,
        Spawn = sys::GPGME_PROTOCOL_SPAWN as isize,
        Default  = sys::GPGME_PROTOCOL_DEFAULT as isize,
        Unknown = sys::GPGME_PROTOCOL_UNKNOWN as isize,
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = unsafe {
            utils::from_cstr(sys::gpgme_get_protocol_name(*self as sys::gpgme_protocol_t))
        };
        write!(f, "{}", name.unwrap_or("Unknown"))
    }
}

struct TokenImp {
    version: &'static str,
    engine_info: RwLock<()>,
}

impl fmt::Debug for TokenImp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "")
    }
}

lazy_static! {
    static ref TOKEN: Token = {
        let version = unsafe {
            let base: sys::_gpgme_signature = mem::zeroed();
            let offset = (&base.validity as *const _ as usize) - (&base as *const _ as usize);

            let result = sys::gpgme_check_version_internal(ptr::null(), offset as libc::size_t);
            utils::from_cstr(result).unwrap()
        };
        Token(Arc::new(TokenImp { version: version, engine_info: RwLock::new(()) }))
    };
}

/// Initializes the gpgme library.
///
///
/// # Examples
///
/// ```no_run
/// let gpgme = gpgme::init();
/// ```
pub fn init() -> Token {
    TOKEN.clone()
}

/// Creates a new context for cryptographic operations.
///
/// # Examples
///
/// ```no_run
/// let mut ctx = gpgme::create_context().unwrap();
/// ```
pub fn create_context() -> Result<Context> {
    Context::new(init())
}

/// A type for managing global resources within the library.
#[derive(Debug, Clone)]
pub struct Token(Arc<TokenImp>);

impl Token {
    /// Checks that the linked version of the library is at least the
    /// specified version.
    ///
    /// Note: `false` is returned, if `version` is not in the format `MAJOR.MINOR.MICRO`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let gpgme = gpgme::init();
    /// assert!(gpgme.check_version("1.4.0"));
    /// ```
    pub fn check_version<S: Into<String>>(&self, version: S) -> bool {
        let version = match CString::new(version.into()) {
            Ok(v) => v,
            Err(_) => return false,
        };
        unsafe {
            !sys::gpgme_check_version(version.as_ptr()).is_null()
        }
    }

    /// Returns the version string for the library.
    pub fn version(&self) -> &'static str {
        self.0.version
    }

    /// Returns the default value for specified configuration option.
    ///
    /// Commonly supported values for `what` are specified in [`info`](info/).
    ///
    /// This function requires a version of GPGme >= 1.5.0.
    pub fn get_dir_info<S: Into<String>>(&self, what: S) -> Option<&'static str> {
        let what = try_opt!(CString::new(what.into()).ok());
        unsafe {
            utils::from_cstr(sys::gpgme_get_dirinfo(what.as_ptr()))
        }
    }

    /// Checks that the engine implementing the protocol `proto` meets requirements of
    /// the library.
    pub fn check_engine_version(&self, proto: Protocol) -> Result<()> {
        unsafe {
            return_err!(sys::gpgme_engine_check_version(proto as sys::gpgme_protocol_t));
        }
        Ok(())
    }

    pub fn engine_info(&self) -> Result<EngineInfoGuard> {
        EngineInfoGuard::new(&TOKEN)
    }

    pub fn set_engine_info(&self, proto: Protocol, filename: Option<String>,
                           home_dir: Option<String>) -> Result<()> {
        let filename = try!(filename.map_or(Ok(None), |s| CString::new(s).map(Some)));
        let home_dir = try!(home_dir.map_or(Ok(None), |s| CString::new(s).map(Some)));
        unsafe {
            let filename = filename.map_or(ptr::null(), |s| s.as_ptr());
            let home_dir = home_dir.map_or(ptr::null(), |s| s.as_ptr());
            let _lock = self.0.engine_info.write().unwrap();
            return_err!(sys::gpgme_set_engine_info(proto as sys::gpgme_protocol_t,
                                                  filename, home_dir));
        }
        Ok(())
    }
}
