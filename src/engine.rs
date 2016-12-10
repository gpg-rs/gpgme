use std::ffi::CStr;
use std::marker::PhantomData;
use std::ptr;
use std::result;
use std::str::Utf8Error;
use std::sync::RwLockReadGuard;

use ffi;

use {Protocol, TOKEN, Token};
use error::Result;

#[derive(Debug, Copy, Clone)]
pub struct EngineInfo<'a, T: 'a> {
    raw: ffi::gpgme_engine_info_t,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> EngineInfo<'a, T> {
    pub unsafe fn from_raw<'b>(raw: ffi::gpgme_engine_info_t) -> EngineInfo<'b, T> {
        debug_assert!(!raw.is_null());
        EngineInfo {
            raw: raw,
            phantom: PhantomData,
        }
    }

    pub fn raw(&self) -> ffi::gpgme_engine_info_t {
        self.raw
    }

    /// Returns the `Protocol` implemented by the engine.
    pub fn protocol(&self) -> Protocol {
        unsafe { Protocol::from_raw((*self.raw).protocol) }
    }

    pub fn path(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.path_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn path_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.raw).file_name.as_ref().map(|s| CStr::from_ptr(s))
        }
    }

    pub fn home_dir(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.home_dir_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn home_dir_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.raw).home_dir.as_ref().map(|s| CStr::from_ptr(s))
        }
    }

    pub fn version(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.version_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn version_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.raw).version.as_ref().map(|s| CStr::from_ptr(s))
        }
    }

    pub fn required_version(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.required_version_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn required_version_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.raw).req_version.as_ref().map(|s| CStr::from_ptr(s))
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct EngineInfoIter<'a, T: 'a> {
    current: ffi::gpgme_engine_info_t,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> EngineInfoIter<'a, T> {
    pub unsafe fn from_list<'b>(raw: ffi::gpgme_engine_info_t) -> EngineInfoIter<'b, T> {
        EngineInfoIter {
            current: raw,
            phantom: PhantomData,
        }
    }
}

impl<'a, T> Iterator for EngineInfoIter<'a, T> {
    list_iterator!(EngineInfo<'a, T>, EngineInfo::from_raw);
}

pub struct EngineInfoGuard(RwLockReadGuard<'static, ()>);

impl EngineInfoGuard {
    pub fn new(_token: &Token) -> Result<EngineInfoGuard> {
        let lock = TOKEN.0.engine_info.read().expect("Engine info lock could not be acquired");
        unsafe {
            let mut info = ptr::null_mut();
            return_err!(ffi::gpgme_get_engine_info(&mut info));
        }
        Ok(EngineInfoGuard(lock))
    }

    pub fn get(&self, proto: Protocol) -> Option<EngineInfo<()>> {
        self.iter().find(|info| info.protocol() == proto)
    }

    pub fn iter(&self) -> EngineInfoIter<()> {
        unsafe {
            let mut first = ptr::null_mut();
            assert_eq!(ffi::gpgme_get_engine_info(&mut first), 0);
            EngineInfoIter::from_list(first)
        }
    }
}

impl<'a> IntoIterator for &'a EngineInfoGuard {
    type Item = EngineInfo<'a, ()>;
    type IntoIter = EngineInfoIter<'a, ()>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
