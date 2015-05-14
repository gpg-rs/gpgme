#![allow(dead_code)]
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

use gpgme_sys as sys;

pub use self::error::{Result, Error};
pub use self::keys::{Validity, Key, KeyAlgorithm, SubKey, UserId};
pub use self::context::{Protocol, Context};
pub use self::data::{DataEncoding, DataType, Data};

mod error;
mod keys;
mod context;
mod data;
pub mod ops;

pub fn init(required_version: Option<&str>) -> Option<&'static str> {
    unsafe {
        let base: sys::_gpgme_signature = mem::zeroed();
        let offset = (&base.validity as *const _ as usize) - (&base as *const _ as usize);

        let version = required_version.and_then(|x| CString::new(x).ok());
        let result = sys::gpgme_check_version_internal(version.map_or(ptr::null(), |x| x.as_ptr()),
                                                       offset as libc::size_t);
        if !result.is_null() {
            str::from_utf8(CStr::from_ptr(result as *const _).to_bytes()).ok()
        } else {
            None
        }
    }
}
