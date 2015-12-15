use std::marker::PhantomData;

use ffi;

use utils;

bitflags! {
    flags Flags: ffi::gpgme_sig_notation_flags_t {
        const HUMAN_READABLE = ffi::GPGME_SIG_NOTATION_HUMAN_READABLE,
        const CRITICAL = ffi::GPGME_SIG_NOTATION_CRITICAL,
    }
}

pub struct SignatureNotation<'a, T: 'a> {
    raw: ffi::gpgme_sig_notation_t,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> SignatureNotation<'a, T> {
    pub unsafe fn from_raw<'b>(raw: ffi::gpgme_sig_notation_t) -> SignatureNotation<'b, T> {
        debug_assert!(!raw.is_null());
        SignatureNotation {
            raw: raw,
            phantom: PhantomData,
        }
    }

    pub fn raw(&self) -> ffi::gpgme_sig_notation_t {
        self.raw
    }

    pub fn is_human_readable(&self) -> bool {
        unsafe { (*self.raw).human_readable() }
    }

    pub fn is_critical(&self) -> bool {
        unsafe { (*self.raw).critical() }
    }

    pub fn flags(&self) -> Flags {
        unsafe { Flags::from_bits_truncate((*self.raw).flags) }
    }

    pub fn name(&self) -> Option<&'a str> {
        unsafe { utils::from_cstr((*self.raw).name) }
    }

    pub fn value(&self) -> Option<&'a str> {
        unsafe { utils::from_cstr((*self.raw).value) }
    }
}

pub struct SignatureNotationIter<'a, T: 'a> {
    current: ffi::gpgme_sig_notation_t,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> SignatureNotationIter<'a, T> {
    pub unsafe fn from_list<'b>(list: ffi::gpgme_sig_notation_t) -> SignatureNotationIter<'b, T> {
        SignatureNotationIter {
            current: list,
            phantom: PhantomData,
        }
    }
}

impl<'a, T> Iterator for SignatureNotationIter<'a, T> {
    list_iterator!(SignatureNotation<'a, T>, SignatureNotation::from_raw);
}
