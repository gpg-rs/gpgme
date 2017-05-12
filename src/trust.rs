use std::ffi::CStr;
use std::fmt;
use std::str::Utf8Error;

use ffi;

use NonZero;

pub struct TrustItem(NonZero<ffi::gpgme_trust_item_t>);

unsafe impl Send for TrustItem {}
unsafe impl Sync for TrustItem {}

impl Drop for TrustItem {
    #[inline]
    fn drop(&mut self) {
        unsafe { ffi::gpgme_trust_item_unref(self.as_raw()) }
    }
}

impl Clone for TrustItem {
    #[inline]
    fn clone(&self) -> TrustItem {
        unsafe {
            ffi::gpgme_trust_item_ref(self.as_raw());
            TrustItem(self.0)
        }
    }
}

impl TrustItem {
    impl_wrapper!(TrustItem: ffi::gpgme_trust_item_t);

    #[inline]
    pub fn trust_level(&self) -> i32 {
        unsafe { (*self.as_raw()).level.into() }
    }

    #[inline]
    pub fn key_id(&self) -> Result<&str, Option<Utf8Error>> {
        self.key_id_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn key_id_raw(&self) -> Option<&CStr> {
        unsafe { (*self.as_raw()).keyid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn user_id(&self) -> Result<&str, Option<Utf8Error>> {
        self.user_id_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn user_id_raw(&self) -> Option<&CStr> {
        unsafe { (*self.as_raw()).name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn owner_trust(&self) -> Result<&str, Option<Utf8Error>> {
        self.owner_trust_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn owner_trust_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.as_raw())
                .owner_trust
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn validity(&self) -> Result<&str, Option<Utf8Error>> {
        self.validity_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn validity_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.as_raw())
                .validity
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }
}

impl fmt::Debug for TrustItem {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("TrustItem")
            .field("raw", &self.as_raw())
            .field("trust_level", &self.trust_level())
            .field("key_id", &self.key_id_raw())
            .field("user_id", &self.user_id_raw())
            .field("owner_trust", &self.owner_trust_raw())
            .field("validity", &self.validity_raw())
            .finish()
    }
}
