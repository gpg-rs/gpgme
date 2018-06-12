use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::ptr;
use std::result;
use std::str::Utf8Error;
use std::sync::{RwLock, RwLockReadGuard};

use ffi;

use {NonNull, Protocol, Result};

#[derive(Copy, Clone)]
pub struct EngineInfo<'a>(NonNull<ffi::gpgme_engine_info_t>, PhantomData<&'a ()>);

unsafe impl<'a> Send for EngineInfo<'a> {}
unsafe impl<'a> Sync for EngineInfo<'a> {}

impl<'a> EngineInfo<'a> {
    impl_wrapper!(EngineInfo(ffi::gpgme_engine_info_t), PhantomData);

    /// Returns the `Protocol` implemented by the engine.
    #[inline]
    pub fn protocol(&self) -> Protocol {
        unsafe { Protocol::from_raw((*self.as_raw()).protocol) }
    }

    #[inline]
    pub fn path(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.path_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn path_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.as_raw())
                .file_name
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn home_dir(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.home_dir_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn home_dir_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.as_raw())
                .home_dir
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn check_version(&self, v: &str) -> bool {
        self.version()
            .map(|s| {
                let it1 = s.split('.').scan((), |_, x| x.parse::<u8>().ok());
                let it2 = v.split('.').scan((), |_, x| x.parse::<u8>().ok());
                Iterator::ge(it1, it2)
            })
            .unwrap_or(false)
    }

    #[inline]
    pub fn version(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.version_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn version_raw(&self) -> Option<&CStr> {
        unsafe { (*self.as_raw()).version.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn required_version(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.required_version_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn required_version_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.as_raw())
                .req_version
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }
}

impl<'a> fmt::Debug for EngineInfo<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineInfo")
            .field("raw", &self.as_raw())
            .field("protocol", &self.protocol())
            .field("path", &self.path_raw())
            .field("home_dir", &self.home_dir_raw())
            .field("version", &self.version_raw())
            .field("required_version", &self.required_version_raw())
            .finish()
    }
}

impl_list_iterator!(EngineInfos, EngineInfo, ffi::gpgme_engine_info_t);

pub struct EngineInfoGuard(RwLockReadGuard<'static, ()>);

impl EngineInfoGuard {
    pub fn new(lock: &'static RwLock<()>) -> Result<EngineInfoGuard> {
        let lock = lock.read().expect("engine info lock was poisoned");
        unsafe {
            let mut info = ptr::null_mut();
            return_err!(ffi::gpgme_get_engine_info(&mut info));
        }
        Ok(EngineInfoGuard(lock))
    }

    #[inline]
    pub fn get(&self, proto: Protocol) -> Option<EngineInfo<'_>> {
        self.iter().find(|info| info.protocol() == proto)
    }

    #[inline]
    pub fn iter(&self) -> EngineInfos<'_> {
        unsafe {
            let mut first = ptr::null_mut();
            assert_eq!(ffi::gpgme_get_engine_info(&mut first), 0);
            EngineInfos::from_list(first)
        }
    }
}

impl<'a> IntoIterator for &'a EngineInfoGuard {
    type Item = EngineInfo<'a>;
    type IntoIter = EngineInfos<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Debug for EngineInfoGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EngineInfoGuard(..)")
    }
}
