extern crate libc;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate enum_primitive;
#[macro_use]
extern crate lazy_static;
extern crate gpgme_sys;

use std::ffi::{CStr, CString};
use std::fmt;
use std::mem;
use std::ptr;
use std::str;
use std::sync::{Arc, RwLock};

use gpgme_sys as sys;

pub use self::error::{Result, Error, ErrorCode};
pub use self::engine::{EngineInfo, EngineInfoGuard};
pub use self::context::{Context, Keys};
pub use self::keys::{Validity, KeyAlgorithm, HashAlgorithm, Key, KeySignature, SubKey, UserId};
pub use self::data::{DataEncoding, DataType, Data};
pub use self::traits::{PassphraseCallback, ProgressCallback};

pub mod error;
mod engine;
mod context;
mod keys;
mod data;
mod traits;
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
        Default  = sys::GPGME_PROTOCOL_DEFAULT as isize,
        Unknown = sys::GPGME_PROTOCOL_UNKNOWN as isize,
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = unsafe {
            let result = sys::gpgme_get_protocol_name(*self as sys::gpgme_protocol_t);
            if !result.is_null() {
                Some(CStr::from_ptr(result as *const _).to_bytes())
            } else {
                None
            }
        };
        write!(f, "{}", name.and_then(|b| str::from_utf8(b).ok()).unwrap_or("Unknown"))
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
            str::from_utf8(CStr::from_ptr(result as *const _).to_bytes()).unwrap()
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
        let what = match CString::new(what.into()) {
            Ok(s) => s,
            Err(_) => return None,
        };
        unsafe {
            let result = sys::gpgme_get_dirinfo(what.as_ptr());
            if !result.is_null() {
                str::from_utf8(CStr::from_ptr(result).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    /// Checks that the engine implementing the protocol `proto` meets requirements of
    /// the library.
    pub fn check_engine_version(&self, proto: Protocol) -> Result<()> {
        let result = unsafe {
            sys::gpgme_engine_check_version(proto as sys::gpgme_protocol_t)
        };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::new(result))
        }
    }

    pub fn engine_info(&self) -> Result<EngineInfoGuard> {
        EngineInfoGuard::new(&TOKEN)
    }

    pub fn set_engine_info(&self, proto: Protocol, file_name: Option<String>,
                           home_dir: Option<String>) -> Result<()> {
        let file_name = match file_name {
            Some(v) => Some(try!(CString::new(v))),
            None => None,
        };
        let home_dir = match home_dir {
            Some(v) => Some(try!(CString::new(v))),
            None => None,
        };
        let result = unsafe {
            let file_name = file_name.map_or(ptr::null(), |s| s.as_ptr());
            let home_dir = home_dir.map_or(ptr::null(), |s| s.as_ptr());
            let _lock = self.0.engine_info.write().unwrap();
            sys::gpgme_set_engine_info(proto as sys::gpgme_protocol_t,
                                       file_name, home_dir)
        };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::new(result))
        }
    }
}
