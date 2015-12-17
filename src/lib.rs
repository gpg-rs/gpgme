extern crate libc;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate gpg_error;
extern crate gpgme_sys as ffi;

use std::ffi::{CStr, CString};
use std::fmt;
use std::mem;
use std::ptr;
use std::sync::{Arc, RwLock};

use self::engine::EngineInfoGuard;

pub use gpg_error as error;
pub use self::error::{Error, Result};
pub use self::context::Context;
pub use self::data::Data;
pub use self::utils::{StrError, StrResult};

#[macro_use]
mod utils;
pub mod engine;
pub mod context;
pub mod data;
pub mod keys;
pub mod trust;
pub mod notation;
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

ffi_enum_wrapper! {
    #[doc="A cryptographic protocol that may be used with the library."]
    #[doc=""]
    #[doc="Each protocol is implemented by an engine that the library communicates with"]
    #[doc="to perform various operations."]
    pub enum Protocol: ffi::gpgme_protocol_t {
        PROTOCOL_OPENPGP = ffi::GPGME_PROTOCOL_OpenPGP,
        PROTOCOL_CMS = ffi::GPGME_PROTOCOL_CMS,
        PROTOCOL_GPGCONF = ffi::GPGME_PROTOCOL_GPGCONF,
        PROTOCOL_ASSUAN = ffi::GPGME_PROTOCOL_ASSUAN,
        PROTOCOL_G13 = ffi::GPGME_PROTOCOL_G13,
        PROTOCOL_UISERVER = ffi::GPGME_PROTOCOL_UISERVER,
        PROTOCOL_SPAWN = ffi::GPGME_PROTOCOL_SPAWN,
        PROTOCOL_DEFAULT = ffi::GPGME_PROTOCOL_DEFAULT,
        PROTOCOL_UNKNOWN = ffi::GPGME_PROTOCOL_UNKNOWN,
    }
}

impl Protocol {
    pub fn name(&self) -> StrResult<'static> {
        unsafe { utils::from_cstr(ffi::gpgme_get_protocol_name(self.0)) }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name().unwrap_or("Unknown"))
    }
}

ffi_enum_wrapper! {
    pub enum Validity: ffi::gpgme_validity_t {
        VALIDITY_UNKNOWN = ffi::GPGME_VALIDITY_UNKNOWN,
        VALIDITY_UNDEFINED = ffi::GPGME_VALIDITY_UNDEFINED,
        VALIDITY_NEVER = ffi::GPGME_VALIDITY_NEVER,
        VALIDITY_MARGINAL = ffi::GPGME_VALIDITY_MARGINAL,
        VALIDITY_FULL = ffi::GPGME_VALIDITY_FULL,
        VALIDITY_ULTIMATE = ffi::GPGME_VALIDITY_ULTIMATE,
    }
}

impl fmt::Display for Validity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            VALIDITY_UNDEFINED => write!(f, "q"),
            VALIDITY_NEVER => write!(f, "n"),
            VALIDITY_MARGINAL => write!(f, "m"),
            VALIDITY_FULL => write!(f, "f"),
            VALIDITY_ULTIMATE => write!(f, "u"),
            _ => write!(f, "?"),
        }
    }
}

struct TokenImp {
    version: &'static str,
    engine_info: RwLock<()>,
}

impl fmt::Debug for TokenImp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Token")
    }
}

lazy_static! {
    static ref TOKEN: Token = {
        let version = unsafe {
            let base: ffi::_gpgme_signature = mem::zeroed();
            let offset = (&base.validity as *const _ as usize) - (&base as *const _ as usize);

            let result = ffi::gpgme_check_version_internal(ptr::null(), offset as libc::size_t);
            assert!(!result.is_null(), "gpgme library could not be initialized");
            CStr::from_ptr(result).to_str().expect("gpgme version string is not valid utf-8")
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
    pub fn check_version<S: Into<Vec<u8>>>(&self, version: S) -> bool {
        let version = match CString::new(version) {
            Ok(v) => v,
            Err(..) => return false,
        };
        unsafe { !ffi::gpgme_check_version(version.as_ptr()).is_null() }
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
    pub fn get_dir_info<S: Into<Vec<u8>>>(&self, what: S) -> utils::StrResult<'static> {
        let what = try!(CString::new(what).or(Err(StrError::NotPresent)));
        unsafe { utils::from_cstr(ffi::gpgme_get_dirinfo(what.as_ptr())) }
    }

    /// Checks that the engine implementing the specified protocol is supported by the library.
    pub fn check_engine_version(&self, proto: Protocol) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_engine_check_version(proto.raw()));
        }
        Ok(())
    }

    pub fn engine_info(&self) -> Result<EngineInfoGuard> {
        EngineInfoGuard::new(&TOKEN)
    }

    pub fn set_engine_filename<S>(&self, proto: Protocol, filename: S) -> Result<()>
    where S: Into<Vec<u8>> {
        let filename = try!(CString::new(filename));
        unsafe {
            let _lock = self.0.engine_info.write().expect("Engine info lock could not be acquired");
            return_err!(ffi::gpgme_set_engine_info(proto.raw(), filename.as_ptr(), ptr::null()));
        }
        Ok(())
    }

    pub fn set_engine_home_dir<S>(&self, proto: Protocol, home_dir: S) -> Result<()>
    where S: Into<Vec<u8>> {
        let home_dir = try!(CString::new(home_dir));
        unsafe {
            let _lock = self.0.engine_info.write().expect("Engine info lock could not be acquired");
            return_err!(ffi::gpgme_set_engine_info(proto.raw(), ptr::null(), home_dir.as_ptr()));
        }
        Ok(())
    }

    pub fn set_engine_info<S1, S2>(&self, proto: Protocol, filename: S1, home_dir: S2) -> Result<()>
    where S1: Into<Vec<u8>>, S2: Into<Vec<u8>> {
        let filename = try!(CString::new(filename));
        let home_dir = try!(CString::new(home_dir));
        unsafe {
            let filename = filename.as_ptr();
            let home_dir = home_dir.as_ptr();
            let _lock = self.0.engine_info.write().expect("Engine info lock could not be acquired");
            return_err!(ffi::gpgme_set_engine_info(proto.raw(), filename, home_dir));
        }
        Ok(())
    }
}

pub unsafe trait Wrapper {
    type Raw: Copy;

    unsafe fn from_raw(raw: Self::Raw) -> Self;
    fn as_raw(&self) -> Self::Raw;
    fn into_raw(self) -> Self::Raw
    where Self: Sized {
        let result = self.as_raw();
        mem::forget(self);
        result
    }
}
