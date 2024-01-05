use std::{
    ffi::CStr,
    fmt, ptr,
    str::Utf8Error,
    sync::{Mutex, OnceLock},
};

use self::{
    engine::EngineInfoGuard,
    utils::{convert_err, CStrArgument},
};

#[doc(inline)]
#[allow(deprecated)]
pub use self::{
    callbacks::{
        EditInteractionStatus, EditInteractor, InteractionStatus, Interactor, PassphraseProvider,
        PassphraseRequest, ProgressInfo, ProgressReporter, StatusHandler,
    },
    context::{Context, ContextWithCallbacks},
    data::{Data, IntoData},
    engine::EngineInfo,
    error::{Error, Result},
    flags::*,
    keys::{Key, Subkey, UserId, UserIdSignature},
    notation::SignatureNotation,
    results::{
        DecryptionResult, EncryptionResult, Import, ImportResult, InvalidKey, KeyGenerationResult,
        KeyListResult, NewSignature, PkaTrust, QuerySwdbResult, Recipient, Signature,
        SigningResult, VerificationResult,
    },
    tofu::{TofuInfo, TofuPolicy},
};
#[doc(inline)]
pub use gpg_error as error;

#[macro_use]
mod utils;
mod callbacks;
pub mod context;
pub mod data;
pub mod edit;
pub mod engine;
mod flags;
pub mod keys;
pub mod notation;
pub mod results;
pub mod tofu;

ffi_enum_wrapper! {
    /// A cryptographic protocol that may be used with the library.
    ///
    /// Each protocol is implemented by an engine that the library communicates with
    /// to perform various operations.
    ///
    /// Upstream documentation:
    /// [`gpgme_protocol_t`](https://www.gnupg.org/documentation/manuals/gpgme/Protocols-and-Engines.html#index-enum-gpgme_005fprotocol_005ft)
    #[non_exhaustive]
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
    /// Upstream documentation:
    /// [`gpgme_get_protocol_name`](https://www.gnupg.org/documentation/manuals/gpgme/Protocols-and-Engines.html#index-gpgme_005fget_005fprotocol_005fname)
    #[inline]
    pub fn name(&self) -> Result<&'static str, Option<Utf8Error>> {
        self.name_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    /// Upstream documentation:
    /// [`gpgme_get_protocol_name`](https://www.gnupg.org/documentation/manuals/gpgme/Protocols-and-Engines.html#index-gpgme_005fget_005fprotocol_005fname)
    #[inline]
    pub fn name_raw(&self) -> Option<&'static CStr> {
        unsafe {
            ffi::gpgme_get_protocol_name(self.raw())
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name().unwrap_or("Unknown"))
    }
}

ffi_enum_wrapper! {
    /// Upstream documentation:
    /// [`gpgme_validity_t`](https://www.gnupg.org/documentation/manuals/gpgme/Information-About-Keys.html#index-gpgme_005fvalidity_005ft)
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

fn get_flag_lock() -> &'static Mutex<()> {
    static FLAG_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    FLAG_LOCK.get_or_init(Mutex::default)
}

/// Upstream documentation:
/// [`gpgme_set_global_flag`](https://www.gnupg.org/documentation/manuals/gpgme/Library-Version-Check.html#index-gpgme_005fset_005fglobal_005fflag)
pub fn set_flag(name: impl CStrArgument, val: impl CStrArgument) -> Result<()> {
    let name = name.into_cstr();
    let val = val.into_cstr();
    let _lock = get_flag_lock().lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        if ffi::gpgme_set_global_flag(name.as_ref().as_ptr(), val.as_ref().as_ptr()) == 0 {
            Ok(())
        } else {
            Err(Error::GENERAL)
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "v1_23")] {
        const MIN_VERSION: &[u8] = b"1.23.0\0";
    } else if #[cfg(feature = "v1_22")] {
        const MIN_VERSION: &[u8] = b"1.22.0\0";
    } else if #[cfg(feature = "v1_21")] {
        const MIN_VERSION: &[u8] = b"1.21.0\0";
    } else if #[cfg(feature = "v1_20")] {
        const MIN_VERSION: &[u8] = b"1.20.0\0";
    } else if #[cfg(feature = "v1_19")] {
        const MIN_VERSION: &[u8] = b"1.19.0\0";
    } else if #[cfg(feature = "v1_18")] {
        const MIN_VERSION: &[u8] = b"1.18.0\0";
    } else if #[cfg(feature = "v1_17")] {
        const MIN_VERSION: &[u8] = b"1.17.0\0";
    } else if #[cfg(feature = "v1_16")] {
        const MIN_VERSION: &[u8] = b"1.16.0\0";
    } else if #[cfg(feature = "v1_15")] {
        const MIN_VERSION: &[u8] = b"1.15.0\0";
    } else if #[cfg(feature = "v1_14")] {
        const MIN_VERSION: &[u8] = b"1.14.0\0";
    } else {
        const MIN_VERSION: &[u8] = b"1.13.0\0";
    }
}

/// Initializes the gpgme library.
///
/// Upstream documentation:
/// [`gpgme_check_version`](https://www.gnupg.org/documentation/manuals/gpgme/Library-Version-Check.html#index-gpgme_005fcheck_005fversion)
///
/// # Examples
///
/// ```no_run
/// let gpgme = gpgme::init();
/// ```
#[inline]
pub fn init() -> Gpgme {
    static TOKEN: OnceLock<&str> = OnceLock::new();
    let token = TOKEN.get_or_init(|| unsafe {
        let offset = memoffset::offset_of!(ffi::_gpgme_signature, validity);

        let result = ffi::gpgme_check_version_internal(MIN_VERSION.as_ptr().cast(), offset);
        assert!(
            !result.is_null(),
            "the library linked is not the correct version"
        );
        CStr::from_ptr(result)
            .to_str()
            .expect("gpgme version string is not valid utf-8")
    });
    Gpgme { version: token }
}

/// A type for managing the library's configuration.
#[derive(Debug, Clone)]
pub struct Gpgme {
    version: &'static str,
}

impl Gpgme {
    pub const HOME_DIR: &'static str = "homedir";
    pub const AGENT_SOCKET: &'static str = "agent-socket";
    pub const UISERVER_SOCKET: &'static str = "uiserver-socket";
    pub const GPGCONF_NAME: &'static str = "gpgconf-name";
    pub const GPG_NAME: &'static str = "gpg-name";
    pub const GPGSM_NAME: &'static str = "gpgsm-name";
    pub const G13_NAME: &'static str = "g13-name";

    /// Checks that the linked version of the library is at least the
    /// specified version.
    ///
    /// Note: `false` is returned, if `version` is not in the format `MAJOR.MINOR.MICRO`.
    ///
    /// Upstream documentation:
    /// [`gpgme_check_version`](https://www.gnupg.org/documentation/manuals/gpgme/Library-Version-Check.html#index-gpgme_005fcheck_005fversion)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let gpgme = gpgme::init();
    /// assert!(gpgme.check_version("1.4.0"));
    /// ```
    #[inline]
    pub fn check_version(&self, version: impl CStrArgument) -> bool {
        let version = version.into_cstr();
        unsafe { !ffi::gpgme_check_version(version.as_ref().as_ptr()).is_null() }
    }

    /// Returns the version string for the library.
    #[inline]
    pub fn version(&self) -> &'static str {
        self.version
    }

    /// Returns the default value for specified configuration option.
    ///
    /// Commonly supported values for `what` are provided as associated constants.
    ///
    /// Upstream documentation:
    /// [`gpgme_get_dirinfo`](https://www.gnupg.org/documentation/manuals/gpgme/Engine-Version-Check.html#index-gpgme_005fget_005fdirinfo)
    #[inline]
    pub fn get_dir_info(&self, what: impl CStrArgument) -> Result<&'static str, Option<Utf8Error>> {
        self.get_dir_info_raw(what)
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    /// Returns the default value for specified configuration option.
    ///
    /// Commonly supported values for `what` are provided as associated constants.
    ///
    /// Upstream documentation:
    /// [`gpgme_get_dirinfo`](https://www.gnupg.org/documentation/manuals/gpgme/Engine-Version-Check.html#index-gpgme_005fget_005fdirinfo)
    #[inline]
    pub fn get_dir_info_raw(&self, what: impl CStrArgument) -> Option<&'static CStr> {
        let what = what.into_cstr();
        unsafe {
            ffi::gpgme_get_dirinfo(what.as_ref().as_ptr())
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    /// Checks that the engine implementing the specified protocol is available.
    ///
    /// Upstream documentation:
    /// [`gpgme_engine_check_version`](https://www.gnupg.org/documentation/manuals/gpgme/Engine-Version-Check.html#index-gpgme_005fengine_005fcheck_005fversion)
    pub fn check_engine_version(&self, proto: Protocol) -> Result<()> {
        unsafe {
            convert_err(ffi::gpgme_engine_check_version(proto.raw()))?;
        }
        Ok(())
    }

    /// Returns an iterator yielding information on each of the globally configured engines.
    ///
    /// Upstream documentation:
    /// [`gpgme_get_engine_info`](https://www.gnupg.org/documentation/manuals/gpgme/Engine-Information.html#index-gpgme_005fget_005fengine_005finfo)
    #[inline]
    pub fn engine_info(&self) -> Result<EngineInfoGuard> {
        EngineInfoGuard::new()
    }

    #[inline]
    pub fn set_engine_path(&self, proto: Protocol, path: impl CStrArgument) -> Result<()> {
        let path = path.into_cstr();
        unsafe {
            let home_dir = self
                .engine_info()?
                .get(proto)
                .as_ref()
                .and_then(|x| x.home_dir_raw())
                .map_or(ptr::null(), |x| x.as_ptr());
            convert_err(ffi::gpgme_set_engine_info(
                proto.raw(),
                path.as_ref().as_ptr(),
                home_dir,
            ))?;
        }
        Ok(())
    }

    #[inline]
    pub fn set_engine_home_dir(&self, proto: Protocol, home_dir: impl CStrArgument) -> Result<()> {
        let home_dir = home_dir.into_cstr();
        unsafe {
            let path = self
                .engine_info()?
                .get(proto)
                .as_ref()
                .and_then(|x| x.path_raw())
                .map_or(ptr::null(), |x| x.as_ptr());
            convert_err(ffi::gpgme_set_engine_info(
                proto.raw(),
                path,
                home_dir.as_ref().as_ptr(),
            ))?;
        }
        Ok(())
    }

    /// Upstream documentation:
    /// [`gpgme_set_engine_info`](https://www.gnupg.org/documentation/manuals/gpgme/Engine-Configuration.html#index-gpgme_005fset_005fengine_005finfo)
    #[inline]
    pub fn set_engine_info(
        &self,
        proto: Protocol,
        path: Option<impl CStrArgument>,
        home_dir: Option<impl CStrArgument>,
    ) -> Result<()> {
        let path = path.map(CStrArgument::into_cstr);
        let home_dir = home_dir.map(CStrArgument::into_cstr);
        let path = path.as_ref().map_or(ptr::null(), |s| s.as_ref().as_ptr());
        let home_dir = home_dir
            .as_ref()
            .map_or(ptr::null(), |s| s.as_ref().as_ptr());
        unsafe {
            convert_err(ffi::gpgme_set_engine_info(proto.raw(), path, home_dir))?;
        }
        Ok(())
    }
}

type NonNull<T> = ptr::NonNull<<T as utils::Ptr>::Inner>;
