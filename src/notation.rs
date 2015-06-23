use std::ffi::CStr;
use std::marker::PhantomData;
use std::str;

use gpgme_sys as sys;

bitflags! {
    flags SignatureNotationFlags: sys::gpgme_sig_notation_flags_t {
        const NOTATION_HUMAN_READABLE = sys::GPGME_SIG_NOTATION_HUMAN_READABLE,
        const NOTATION_CRITICAL = sys::GPGME_SIG_NOTATION_CRITICAL,
    }
}

pub struct SignatureNotation<'a, T: 'a> {
    raw: sys::gpgme_sig_notation_t,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> SignatureNotation<'a, T> {
    pub unsafe fn from_raw<'b>(raw: sys::gpgme_sig_notation_t) -> SignatureNotation<'b, T> {
        SignatureNotation { raw: raw, phantom: PhantomData }
    }

    pub fn as_raw(&self) -> sys::gpgme_sig_notation_t {
        self.raw
    }

    pub fn is_human_readable(&self) -> bool {
        unsafe { (*self.raw).human_readable() }
    }

    pub fn is_critical(&self) -> bool {
        unsafe { (*self.raw).critical() }
    }

    pub fn flags(&self) -> SignatureNotationFlags {
        unsafe {
            SignatureNotationFlags::from_bits_truncate((*self.raw).flags)
        }
    }

    pub fn name(&self) -> Option<&'a str> {
        unsafe {
            let name = (*self.raw).name;
            if !name.is_null() {
                str::from_utf8(CStr::from_ptr(name).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    pub fn value(&self) -> Option<&'a str> {
        unsafe {
            let value = (*self.raw).value;
            if !value.is_null() {
                str::from_utf8(CStr::from_ptr(value).to_bytes()).ok()
            } else {
                None
            }
        }
    }
}

pub struct SignatureNotationIter<'a, T: 'a> {
    current: sys::gpgme_sig_notation_t,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> SignatureNotationIter<'a, T> {
    pub unsafe fn from_list<'b>(list: sys::gpgme_sig_notation_t) -> SignatureNotationIter<'b, T> {
        SignatureNotationIter { current: list, phantom: PhantomData }
    }
}

impl<'a, T> Iterator for SignatureNotationIter<'a, T> {
    type Item = SignatureNotation<'a, T>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current;
        if !current.is_null() {
            unsafe {
                self.current = (*current).next;
                Some(SignatureNotation::from_raw(current))
            }
        } else {
            None
        }
    }
}
