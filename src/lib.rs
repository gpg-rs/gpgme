extern crate libc;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate enum_primitive;
extern crate gpgme_sys;

use std::ffi::{CStr, CString};
use std::mem;
use std::ptr;
use std::str;
use std::sync::{Arc, Mutex, Once, ONCE_INIT};

use gpgme_sys as sys;

pub use self::error::{Result, Error, ErrorCode};
pub use self::keys::{Validity, KeyAlgorithm, HashAlgorithm, Key, KeySignature, SubKey, UserId};
pub use self::context::{Protocol, Context};
pub use self::data::{DataEncoding, DataType, Data};

mod error;
mod keys;
mod context;
mod data;
pub mod ops;

#[derive(Debug)]
struct GpgMeImp {
    version: &'static str,
    guard: Mutex<()>,
}

#[derive(Debug, Clone)]
pub struct GpgMe(Arc<GpgMeImp>);

impl GpgMe {
    pub fn check_version<S: Into<String>>(&self, version: S) -> bool {
        let version = match CString::new(version.into()) {
            Ok(v) => v,
            Err(_) => return false,
        };
        unsafe {
            !sys::gpgme_check_version(version.as_ptr()).is_null()
        }
    }

    pub fn version(&self) -> &'static str {
        self.0.version
    }
}

/// Initializes the gpgme library.
///
/// # Failures
///
/// This function returns `None` if the library was already initialized.
///
/// # Examples
///
/// ```no_run
/// let gpgme = gpgme::init().unwrap();
/// ```
pub fn init() -> Option<GpgMe> {
    static INIT: Once = ONCE_INIT;

    let mut gpgme: Option<GpgMeImp> = None;
    INIT.call_once(|| {
        let version = unsafe {
            let base: sys::_gpgme_signature = mem::zeroed();
            let offset = (&base.validity as *const _ as usize) - (&base as *const _ as usize);

            let result = sys::gpgme_check_version_internal(ptr::null(), offset as libc::size_t);
            str::from_utf8(CStr::from_ptr(result as *const _).to_bytes()).unwrap()
        };
        gpgme = Some(GpgMeImp { version: version, guard: Mutex::new(()) })
    });
    gpgme.map(|x| GpgMe(Arc::new(x)))
}
