#![warn(trivial_numeric_casts)]
#![deny(missing_debug_implementations)]
#![cfg_attr(any(nightly, feature="nightly"), feature(nonzero))]
extern crate core;
extern crate libc;
#[macro_use]
extern crate cfg_if;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate lazy_static;
extern crate conv;
extern crate gpgme_sys as ffi;
#[macro_use]
pub extern crate gpg_error as error;

use std::ffi::CStr;
use std::fmt;
use std::mem;
use std::ptr;
use std::result;
use std::str::Utf8Error;
use std::sync::{Arc, RwLock};

use self::engine::EngineInfoGuard;

pub use self::flags::*;
pub use self::utils::IntoNativeString;
pub use self::error::{Error, Result};
pub use self::data::{Data, IntoData};
pub use self::context::Context;
pub use self::keys::{Key, Subkey, UserId, UserIdSignature};
pub use self::notation::SignatureNotation;
pub use self::trust::TrustItem;
pub use self::tofu::{TofuInfo, TofuPolicy};
pub use self::callbacks::{EditInteractionStatus, EditInteractor, InteractionStatus, Interactor,
                          PassphraseProvider, PassphraseRequest, ProgressHandler, ProgressInfo,
                          StatusHandler};
pub use self::results::{DecryptionResult, EncryptionResult, Import, ImportResult, InvalidKey,
                        KeyGenerationResult, KeyListResult, NewSignature, PkaTrust, Recipient,
                        Signature, SigningResult, VerificationResult};
pub use self::engine::EngineInfo;

#[macro_use]
mod utils;
mod callbacks;
mod flags;
pub mod results;
pub mod engine;
pub mod context;
pub mod data;
pub mod keys;
pub mod trust;
pub mod notation;
pub mod tofu;
pub mod edit;

/// Constants for use with `Token::get_dir_info`.
#[cfg(feature = "v1_5_0")]
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
        OpenPgp = ffi::GPGME_PROTOCOL_OpenPGP,
        Cms = ffi::GPGME_PROTOCOL_CMS,
        GpgConf = ffi::GPGME_PROTOCOL_GPGCONF,
        Assuan = ffi::GPGME_PROTOCOL_ASSUAN,
        G13 = ffi::GPGME_PROTOCOL_G13,
        UiServer = ffi::GPGME_PROTOCOL_UISERVER,
        Spawn = ffi::GPGME_PROTOCOL_SPAWN,
        Default = ffi::GPGME_PROTOCOL_DEFAULT,
        Unknown = ffi::GPGME_PROTOCOL_UNKNOWN,
    }
}

impl Protocol {
    #[inline]
    pub fn name(&self) -> result::Result<&'static str, Option<Utf8Error>> {
        self.name_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn name_raw(&self) -> Option<&'static CStr> {
        unsafe { ffi::gpgme_get_protocol_name(self.raw()).as_ref().map(|s| CStr::from_ptr(s)) }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name().unwrap_or("Unknown"))
    }
}

ffi_enum_wrapper! {
    pub enum Validity(Unknown): ffi::gpgme_validity_t {
        Unknown = ffi::GPGME_VALIDITY_UNKNOWN,
        Undefined = ffi::GPGME_VALIDITY_UNDEFINED,
        Never = ffi::GPGME_VALIDITY_NEVER,
        Marginal = ffi::GPGME_VALIDITY_MARGINAL,
        Full = ffi::GPGME_VALIDITY_FULL,
        Ultimate = ffi::GPGME_VALIDITY_ULTIMATE,
    }
}

impl fmt::Display for Validity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Validity::Undefined => write!(f, "q"),
            Validity::Never => write!(f, "n"),
            Validity::Marginal => write!(f, "m"),
            Validity::Full => write!(f, "f"),
            Validity::Ultimate => write!(f, "u"),
            _ => write!(f, "?"),
        }
    }
}

cfg_if! {
    if #[cfg(feature = "v1_8_0")] {
        const TARGET_VERSION: &'static str = "1.8.0\0";
    } else if #[cfg(feature = "v1_7_1")] {
        const TARGET_VERSION: &'static str = "1.7.1\0";
    } else if #[cfg(feature = "v1_7_0")] {
        const TARGET_VERSION: &'static str = "1.7.0\0";
    } else if #[cfg(feature = "v1_6_0")] {
        const TARGET_VERSION: &'static str = "1.6.0\0";
    } else if #[cfg(feature = "v1_5_1")] {
        const TARGET_VERSION: &'static str = "1.5.1\0";
    } else if #[cfg(feature = "v1_5_0")] {
        const TARGET_VERSION: &'static str = "1.5.0\0";
    } else if #[cfg(feature = "v1_4_3")] {
        const TARGET_VERSION: &'static str = "1.4.3\0";
    } else if #[cfg(feature = "v1_4_2")] {
        const TARGET_VERSION: &'static str = "1.4.2\0";
    } else if #[cfg(feature = "v1_4_0")] {
        const TARGET_VERSION: &'static str = "1.4.0\0";
    } else if #[cfg(feature = "v1_3_1")] {
        const TARGET_VERSION: &'static str = "1.3.1\0";
    } else if #[cfg(feature = "v1_3_0")] {
        const TARGET_VERSION: &'static str = "1.3.0\0";
    } else {
        const TARGET_VERSION: &'static str = "1.2.0\0";
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

            let result = ffi::gpgme_check_version_internal(TARGET_VERSION.as_ptr() as *const _,
                                                           offset);
            assert!(!result.is_null(), "gpgme library could not be initialized for version: {}",
                    TARGET_VERSION);
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
#[inline]
pub fn init() -> Token {
    TOKEN.clone()
}

cfg_if! {
    if #[cfg(feature = "v1_4_0")] {
        use std::sync::Mutex;

        lazy_static! {
            static ref FLAG_LOCK: Mutex<()> = Mutex::default();
        }

        pub fn set_flag<S1, S2>(name: S1, val: S2) -> Result<()>
        where S1: IntoNativeString, S2: IntoNativeString {
            let name = name.into_native();
            let val = val.into_native();
            let _lock = FLAG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            unsafe {
                if ffi::gpgme_set_global_flag(name.as_ref().as_ptr(), val.as_ref().as_ptr()) == 0 {
                    Ok(())
                } else {
                    Err(Error::new(error::GPG_ERR_GENERAL))
                }
            }
        }
    } else {
        pub fn set_flag<S1, S2>(_name: S1, _val: S2) -> Result<()>
        where S1: IntoNativeString, S2: IntoNativeString {
            Err(Error::new(error::GPG_ERR_GENERAL))
        }
    }
}

/// A type for managing the library's configuration.
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
    #[inline]
    pub fn check_version<S: IntoNativeString>(&self, version: S) -> bool {
        let version = version.into_native();
        unsafe { !ffi::gpgme_check_version(version.as_ref().as_ptr()).is_null() }
    }

    /// Returns the version string for the library.
    #[inline]
    pub fn version(&self) -> &'static str {
        self.0.version
    }

    /// Returns the default value for specified configuration option.
    ///
    /// Commonly supported values for `what` are specified in [`info`](info/).
    #[inline]
    pub fn get_dir_info<S>(&self, what: S) -> result::Result<&'static str, Option<Utf8Error>>
    where S: IntoNativeString {
        self.get_dir_info_raw(what).map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    /// Returns the default value for specified configuration option.
    ///
    /// Commonly supported values for `what` are specified in [`info`](info/).
    #[inline]
    #[cfg(feature = "v1_5_0")]
    pub fn get_dir_info_raw<S: IntoNativeString>(&self, what: S) -> Option<&'static CStr> {
        let what = what.into_native();
        unsafe {
            ffi::gpgme_get_dirinfo(what.as_ref().as_ptr()).as_ref().map(|s| CStr::from_ptr(s))
        }
    }

    /// Returns the default value for specified configuration option.
    ///
    /// Commonly supported values for `what` are specified in [`info`](info/).
    #[inline]
    #[cfg(not(feature = "v1_5_0"))]
    pub fn get_dir_info_raw<S: IntoNativeString>(&self, _what: S) -> Option<&'static CStr> {
        None
    }

    /// Checks that the engine implementing the specified protocol is supported by the library.
    pub fn check_engine_version(&self, proto: Protocol) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_engine_check_version(proto.raw()));
        }
        Ok(())
    }

    #[inline]
    pub fn engine_info(&self) -> Result<EngineInfoGuard> {
        EngineInfoGuard::new(&TOKEN)
    }

    unsafe fn get_engine_info(&self, proto: Protocol) -> ffi::gpgme_engine_info_t {
        let mut info = ptr::null_mut();
        assert_eq!(ffi::gpgme_get_engine_info(&mut info), 0);
        while !info.is_null() && ((*info).protocol != proto.raw()) {
            info = (*info).next;
        }
        info
    }

    #[inline]
    pub fn set_engine_path<S>(&self, proto: Protocol, path: S) -> Result<()>
    where S: IntoNativeString {
        let path = path.into_native();
        unsafe {
            let _lock = self.0.engine_info.write().expect("Engine info lock could not be acquired");
            let home_dir = self.get_engine_info(proto).as_ref().map_or(ptr::null(), |e| {
                (*e).home_dir
            });
            return_err!(ffi::gpgme_set_engine_info(proto.raw(), path.as_ref().as_ptr(),
                                                   home_dir));
        }
        Ok(())
    }

    #[inline]
    pub fn set_engine_home_dir<S>(&self, proto: Protocol, home_dir: S) -> Result<()>
    where S: IntoNativeString {
        let home_dir = home_dir.into_native();
        unsafe {
            let _lock = self.0.engine_info.write().expect("Engine info lock could not be acquired");
            let path = self.get_engine_info(proto).as_ref().map_or(ptr::null(), |e| {
                (*e).file_name
            });
            return_err!(ffi::gpgme_set_engine_info(proto.raw(), path,
                                                   home_dir.as_ref().as_ptr()));
        }
        Ok(())
    }

    #[inline]
    pub fn set_engine_info<S1, S2>(&self, proto: Protocol,
                                   path: Option<S1>, home_dir: Option<S2>) -> Result<()>
    where S1: IntoNativeString, S2: IntoNativeString {
        let path = path.map(S1::into_native);
        let home_dir = home_dir.map(S2::into_native);
        unsafe {
            let path = path.map_or(ptr::null(), |s| s.as_ref().as_ptr());
            let home_dir = home_dir.map_or(ptr::null(), |s| s.as_ref().as_ptr());
            let _lock = self.0.engine_info.write().expect("Engine info lock could not be acquired");
            return_err!(ffi::gpgme_set_engine_info(proto.raw(), path, home_dir));
        }
        Ok(())
    }
}

unsafe trait OpResult: Clone {
    fn from_context(ctx: &Context) -> Option<Self>;
}

type NonZero<T> = utils::NonZero<T>;
