use std::{
    ffi::CStr,
    fmt,
    marker::PhantomData,
    ptr,
    str::Utf8Error,
    sync::{RwLock, RwLockReadGuard},
};

use ffi;

use crate::{utils::convert_err, NonNull, Protocol, Result};

/// Upstream documentation:
/// [`gpgme_engine_info_t`](https://www.gnupg.org/documentation/manuals/gpgme/Engine-Information.html#index-gpgme_005fengine_005finfo_005ft)
#[derive(Copy, Clone)]
pub struct EngineInfo<'a>(NonNull<ffi::gpgme_engine_info_t>, PhantomData<&'a ()>);

unsafe impl Send for EngineInfo<'_> {}
unsafe impl Sync for EngineInfo<'_> {}

impl EngineInfo<'_> {
    impl_wrapper!(ffi::gpgme_engine_info_t, PhantomData);

    /// Returns the `Protocol` implemented by the engine.
    #[inline]
    pub fn protocol(&self) -> Protocol {
        unsafe { Protocol::from_raw((*self.as_raw()).protocol) }
    }

    #[inline]
    pub fn path(&self) -> Result<&str, Option<Utf8Error>> {
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
    pub fn home_dir(&self) -> Result<&str, Option<Utf8Error>> {
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
    pub fn version(&self) -> Result<&str, Option<Utf8Error>> {
        self.version_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn version_raw(&self) -> Option<&CStr> {
        unsafe { (*self.as_raw()).version.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn required_version(&self) -> Result<&str, Option<Utf8Error>> {
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

impl fmt::Debug for EngineInfo<'_> {
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

impl_list_iterator!(pub struct EngineInfos(EngineInfo: ffi::gpgme_engine_info_t));

/// A RAII guard type that ensures the global engine information list is not modified
/// while it is being iterated.
pub struct EngineInfoGuard(RwLockReadGuard<'static, ()>);

impl EngineInfoGuard {
    pub fn new(lock: &'static RwLock<()>) -> Result<EngineInfoGuard> {
        let lock = lock.read().expect("engine info lock was poisoned");
        unsafe {
            let mut info = ptr::null_mut();
            convert_err(ffi::gpgme_get_engine_info(&mut info))?;
        }
        Ok(EngineInfoGuard(lock))
    }

    #[inline]
    pub fn get(&self, proto: Protocol) -> Option<EngineInfo<'_>> {
        self.into_iter().find(|info| info.protocol() == proto)
    }

    #[inline]
    pub fn iter(&self) -> EngineInfos<'_> {
        self.into_iter()
    }
}

impl<'a> IntoIterator for &'a EngineInfoGuard {
    type Item = EngineInfo<'a>;
    type IntoIter = EngineInfos<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        unsafe {
            let mut first = ptr::null_mut();
            assert_eq!(ffi::gpgme_get_engine_info(&mut first), 0);
            EngineInfos::from_list(first)
        }
    }
}

impl fmt::Debug for EngineInfoGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EngineInfoGuard(..)")
    }
}
