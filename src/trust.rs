use ffi;

use Wrapper;
use utils;

pub struct TrustItem {
    raw: ffi::gpgme_trust_item_t,
}

impl Drop for TrustItem {
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_trust_item_unref(self.raw)
        }
    }
}

impl Clone for TrustItem {
    fn clone(&self) -> TrustItem {
        unsafe {
            ffi::gpgme_trust_item_ref(self.raw);
            TrustItem { raw: self.raw }
        }
    }
}

unsafe impl Wrapper for TrustItem {
    type Raw = ffi::gpgme_trust_item_t;

    unsafe fn from_raw(raw: ffi::gpgme_trust_item_t) -> TrustItem {
        TrustItem { raw: raw }
    }

    fn as_raw(&self) -> ffi::gpgme_trust_item_t {
        self.raw
    }
}

impl TrustItem {
    pub fn level(&self) -> isize {
        unsafe {
            (*self.raw).level as isize
        }
    }

    pub fn key_id(&self) -> Option<&str> {
        unsafe {
            utils::from_cstr((*self.raw).keyid)
        }
    }

    pub fn owner_trust(&self) -> Option<&str> {
        unsafe {
            utils::from_cstr((*self.raw).owner_trust)
        }
    }

    pub fn name(&self) -> Option<&str> {
        unsafe {
            utils::from_cstr((*self.raw).name)
        }
    }

    pub fn validity(&self) -> Option<&str> {
        unsafe {
            utils::from_cstr((*self.raw).validity)
        }
    }
}
