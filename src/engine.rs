use std::marker::PhantomData;
use std::ptr;
use std::sync::RwLockReadGuard;

use ffi;

use {Protocol, TOKEN, Token};
use error::Result;
use utils;

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

    pub fn filename(&self) -> Option<&'a str> {
        unsafe { utils::from_cstr((*self.raw).file_name) }
    }

    pub fn home_dir(&self) -> Option<&'a str> {
        unsafe { utils::from_cstr((*self.raw).home_dir) }
    }

    pub fn version(&self) -> Option<&'a str> {
        unsafe { utils::from_cstr((*self.raw).version) }
    }

    pub fn required_version(&self) -> Option<&'a str> {
        unsafe { utils::from_cstr((*self.raw).req_version) }
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
