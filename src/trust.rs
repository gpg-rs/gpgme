use gpgme_sys as sys;

use utils;

pub struct TrustItem {
    raw: sys::gpgme_trust_item_t,
}

impl TrustItem {
    pub unsafe fn from_raw(raw: sys::gpgme_trust_item_t) -> TrustItem {
        TrustItem { raw: raw }
    }

    pub fn as_raw(&self) -> sys::gpgme_trust_item_t {
        self.raw
    }

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

impl Drop for TrustItem {
    fn drop(&mut self) {
        unsafe {
            sys::gpgme_trust_item_unref(self.raw)
        }
    }
}

impl Clone for TrustItem {
    fn clone(&self) -> TrustItem {
        unsafe {
            sys::gpgme_trust_item_ref(self.raw);
            TrustItem { raw: self.raw }
        }
    }
}
