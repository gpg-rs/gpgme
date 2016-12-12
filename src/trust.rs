use std::ffi::CStr;
use std::str::Utf8Error;

use ffi;

#[derive(Debug)]
pub struct TrustItem(ffi::gpgme_trust_item_t);

impl Drop for TrustItem {
    #[inline]
    fn drop(&mut self) {
        unsafe { ffi::gpgme_trust_item_unref(self.0) }
    }
}

impl Clone for TrustItem {
    #[inline]
    fn clone(&self) -> TrustItem {
        unsafe {
            ffi::gpgme_trust_item_ref(self.0);
            TrustItem(self.0)
        }
    }
}

impl TrustItem {
    impl_wrapper!(TrustItem: ffi::gpgme_trust_item_t);

    #[inline]
    pub fn trust_level(&self) -> i32 {
        unsafe { (*self.0).level.into() }
    }

    #[inline]
    pub fn key_id(&self) -> Result<&str, Option<Utf8Error>> {
        self.key_id_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn key_id_raw(&self) -> Option<&CStr> {
        unsafe { (*self.0).keyid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn user_id(&self) -> Result<&str, Option<Utf8Error>> {
        self.user_id_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn user_id_raw(&self) -> Option<&CStr> {
        unsafe { (*self.0).name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn owner_trust(&self) -> Result<&str, Option<Utf8Error>> {
        self.owner_trust_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn owner_trust_raw(&self) -> Option<&CStr> {
        unsafe { (*self.0).owner_trust.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn validity(&self) -> Result<&str, Option<Utf8Error>> {
        self.validity_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn validity_raw(&self) -> Option<&CStr> {
        unsafe { (*self.0).validity.as_ref().map(|s| CStr::from_ptr(s)) }
    }
}
