use std::error;
use std::ffi::{CStr, NulError};
use std::fmt;
use std::str;

use libc;

use gpgme_sys as sys;

const TMPBUF_SZ: usize = 0x0400;

pub type ErrorCode = sys::gpgme_err_code_t;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct Error {
    err: sys::gpgme_error_t,
}

impl Error {
    pub fn new(err: sys::gpgme_error_t) -> Error {
        Error { err: err }
    }

    pub fn raw(&self) -> sys::gpgme_error_t {
        self.err
    }

    pub fn from_source(source: sys::gpgme_err_source_t, code: sys::gpgme_err_code_t) -> Error {
        Error::new(sys::gpgme_err_make(source, code))
    }

    pub fn last_os_error() -> Error {
        unsafe {
            Error::new(sys::gpgme_error_from_syserror())
        }
    }

    pub fn from_raw_os_error(code: i32) -> Error {
        unsafe {
            Error::new(sys::gpgme_error_from_errno(code as libc::c_int))
        }
    }

    pub fn code(&self) -> ErrorCode {
        sys::gpgme_err_code(self.err)
    }

    pub fn source(&self) -> Option<&'static str> {
        unsafe {
            let result = sys::gpgme_strsource(self.err);
            if !result.is_null() {
                str::from_utf8(CStr::from_ptr(result as *const _).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    pub fn description(&self) -> String {
        let mut buf = [0 as libc::c_char; TMPBUF_SZ];
        let p = buf.as_mut_ptr();
        unsafe {
            if sys::gpgme_strerror_r(self.err, p, buf.len() as libc::size_t) < 0 {
                panic!("gpgme_strerror_r failure")
            }
            str::from_utf8(CStr::from_ptr(p as *const _).to_bytes()).unwrap().to_owned()
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "gpgme error"
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{} (gpgme error {})", self.description(), self.code())
    }
}

impl From<NulError> for Error {
    fn from(_: NulError) -> Error {
        Error::from_source(sys::GPG_ERR_SOURCE_GPGME,
                           sys::GPG_ERR_INV_VALUE)
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;
