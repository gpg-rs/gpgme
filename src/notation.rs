    #![allow(trivial_numeric_casts)]
use std::ffi::CStr;
use std::marker::PhantomData;
use std::str::Utf8Error;

use ffi;

use SignatureNotationFlags;

#[derive(Debug, Copy, Clone)]
pub struct SignatureNotation<'a, T: 'a>(ffi::gpgme_sig_notation_t, PhantomData<&'a T>);

impl<'a, T> SignatureNotation<'a, T> {
    impl_wrapper!(@phantom SignatureNotation: ffi::gpgme_sig_notation_t);

    #[inline]
    pub fn is_human_readable(&self) -> bool {
        unsafe { (*self.0).human_readable() }
    }

    #[inline]
    pub fn is_critical(&self) -> bool {
        unsafe { (*self.0).critical() }
    }

    #[inline]
    pub fn flags(&self) -> SignatureNotationFlags {
        unsafe { SignatureNotationFlags::from_bits_truncate((*self.0).flags) }
    }

    #[inline]
    pub fn name(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.name_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn name_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn value(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.value_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn value_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).value.as_ref().map(|s| CStr::from_ptr(s)) }
    }
}

#[derive(Debug, Clone)]
pub struct SignatureNotations<'a, T: 'a> {
    current: ffi::gpgme_sig_notation_t,
    left: Option<usize>,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> SignatureNotations<'a, T> {
    pub unsafe fn from_list(first: ffi::gpgme_sig_notation_t) -> Self {
        let left = count_list!(first);
        SignatureNotations {
            current: first,
            left: left,
            phantom: PhantomData,
        }
    }
}

impl<'a, T> Iterator for SignatureNotations<'a, T> {
    list_iterator!(SignatureNotation<'a, T>, SignatureNotation::from_raw);
}
