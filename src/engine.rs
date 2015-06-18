use std::ffi::CStr;
use std::marker::PhantomData;
use std::ptr;
use std::str;
use std::sync::RwLockReadGuard;

use enum_primitive::FromPrimitive;

use gpgme_sys as sys;

use {Protocol, Token};
use error::{Error, Result};

#[derive(Debug, Copy, Clone)]
pub struct EngineInfo<'a, T: 'a> {
    raw: sys::gpgme_engine_info_t,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> EngineInfo<'a, T> {
    pub unsafe fn from_raw<'b>(raw: sys::gpgme_engine_info_t) -> EngineInfo<'b, T> {
        EngineInfo { raw: raw, phantom: PhantomData }
    }

    pub fn as_raw(&self) -> sys::gpgme_engine_info_t {
        self.raw
    }

    /// Returns the `Protocol` implemented by the engine.
    pub fn protocol(&self) -> Protocol {
        unsafe {
            Protocol::from_u64((*self.raw).protocol as u64).unwrap_or(Protocol::Unknown)
        }
    }

    pub fn file_name(&self) -> Option<&'a str> {
        unsafe {
            let file_name = (*self.raw).file_name;
            if !file_name.is_null() {
                str::from_utf8(CStr::from_ptr(file_name).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    pub fn home_dir(&self) -> Option<&'a str> {
        unsafe {
            let home_dir = (*self.raw).home_dir;
            if !home_dir.is_null() {
                str::from_utf8(CStr::from_ptr(home_dir).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    pub fn version(&self) -> Option<&'a str> {
        unsafe {
            let version = (*self.raw).version;
            if !version.is_null() {
                str::from_utf8(CStr::from_ptr(version).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    pub fn required_version(&self) -> Option<&'a str> {
        unsafe {
            let req_version = (*self.raw).req_version;
            if !req_version.is_null() {
                str::from_utf8(CStr::from_ptr(req_version).to_bytes()).ok()
            } else {
                None
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct EngineInfoIter<'a, T: 'a> {
    current: sys::gpgme_engine_info_t,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> EngineInfoIter<'a, T> {
    pub unsafe fn from_list<'b>(raw: sys::gpgme_engine_info_t) -> EngineInfoIter<'b, T> {
        EngineInfoIter { current: raw, phantom: PhantomData }
    }
}

impl<'a, T> Iterator for EngineInfoIter<'a, T> {
    type Item = EngineInfo<'a, T>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current;
        if !current.is_null() {
            unsafe {
                self.current = (*current).next;
                Some(EngineInfo::from_raw(current))
            }
        } else {
            None
        }
    }
}

pub struct EngineInfoGuard<'a>(RwLockReadGuard<'a, ()>);

impl<'a> EngineInfoGuard<'a> {
    pub fn new<'b>(lib: &'b Token) -> Result<EngineInfoGuard<'b>> {
        let lock = lib.0.engine_info.read().unwrap();
        let result = unsafe {
            let mut info: sys::gpgme_engine_info_t = ptr::null_mut();
            sys::gpgme_get_engine_info(&mut info)
        };
        if result == 0 {
            Ok(EngineInfoGuard(lock))
        } else {
            Err(Error::new(result))
        }
    }

    pub fn get(&self, proto: Protocol) -> Option<EngineInfo<()>> {
        self.iter().find(|info| info.protocol() == proto)
    }

    pub fn iter(&self) -> EngineInfoIter<()> {
        unsafe {
            let mut first: sys::gpgme_engine_info_t = ptr::null_mut();
            assert_eq!(sys::gpgme_get_engine_info(&mut first), 0);
            EngineInfoIter::from_list(first)
        }
    }
}

impl<'a, 'b> IntoIterator for &'b EngineInfoGuard<'a> {
    type Item = EngineInfo<'b, ()>;
    type IntoIter = EngineInfoIter<'b, ()>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
