use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::ptr;
use std::result;
use std::str::Utf8Error;
use std::sync::RwLockReadGuard;

use ffi;

use {Protocol, TOKEN, Token};
use error::Result;

#[derive(Debug, Copy, Clone)]
pub struct EngineInfo<'a, T: 'a>(ffi::gpgme_engine_info_t, PhantomData<&'a T>);

impl<'a, T> EngineInfo<'a, T> {
    impl_wrapper!(@phantom EngineInfo: ffi::gpgme_engine_info_t);

    /// Returns the `Protocol` implemented by the engine.
    #[inline]
    pub fn protocol(&self) -> Protocol {
        unsafe { Protocol::from_raw((*self.0).protocol) }
    }

    #[inline]
    pub fn path(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.path_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn path_raw(&self) -> Option<&CStr> {
        unsafe { (*self.0).file_name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn home_dir(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.home_dir_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn home_dir_raw(&self) -> Option<&CStr> {
        unsafe { (*self.0).home_dir.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn version(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.version_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn version_raw(&self) -> Option<&CStr> {
        unsafe { (*self.0).version.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn required_version(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.required_version_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn required_version_raw(&self) -> Option<&CStr> {
        unsafe { (*self.0).req_version.as_ref().map(|s| CStr::from_ptr(s)) }
    }
}

#[derive(Debug, Clone)]
pub struct EngineInfos<'a, T: 'a> {
    current: ffi::gpgme_engine_info_t,
    left: Option<usize>,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> EngineInfos<'a, T> {
    #[inline]
    pub unsafe fn from_list<'b>(first: ffi::gpgme_engine_info_t) -> EngineInfos<'b, T> {
        let left = count_list!(first);
        EngineInfos {
            current: first,
            left: left,
            phantom: PhantomData,
        }
    }
}

impl<'a, T> Iterator for EngineInfos<'a, T> {
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

    #[inline]
    pub fn get(&self, proto: Protocol) -> Option<EngineInfo<()>> {
        self.iter().find(|info| info.protocol() == proto)
    }

    #[inline]
    pub fn iter(&self) -> EngineInfos<()> {
        unsafe {
            let mut first = ptr::null_mut();
            assert_eq!(ffi::gpgme_get_engine_info(&mut first), 0);
            EngineInfos::from_list(first)
        }
    }
}

impl<'a> IntoIterator for &'a EngineInfoGuard {
    type Item = EngineInfo<'a, ()>;
    type IntoIter = EngineInfos<'a, ()>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Debug for EngineInfoGuard {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EngineInfoGuard(..)")
    }
}
