use std::marker::PhantomData;

use gpgme_sys as sys;

use utils;

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
            utils::from_cstr((*self.raw).name)
        }
    }

    pub fn value(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).value)
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
    list_iterator!(SignatureNotation<'a, T>, SignatureNotation::from_raw);
}
