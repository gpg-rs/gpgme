    #![allow(trivial_numeric_casts)]
use std::ffi::CStr;
use std::marker::PhantomData;
use std::str::Utf8Error;

use ffi;

use NonZero;
use SignatureNotationFlags;

#[derive(Debug, Copy, Clone)]
pub struct SignatureNotation<'a, T: 'a>(NonZero<ffi::gpgme_sig_notation_t>, PhantomData<&'a T>);

unsafe impl<'a, T> Send for SignatureNotation<'a, T> {}
unsafe impl<'a, T> Sync for SignatureNotation<'a, T> {}

impl<'a, T> SignatureNotation<'a, T> {
    impl_wrapper!(@phantom SignatureNotation: ffi::gpgme_sig_notation_t);

    #[inline]
    pub fn is_human_readable(&self) -> bool {
        unsafe { (*self.as_raw()).human_readable() }
    }

    #[inline]
    pub fn is_critical(&self) -> bool {
        unsafe { (*self.as_raw()).critical() }
    }

    #[inline]
    pub fn flags(&self) -> SignatureNotationFlags {
        unsafe { SignatureNotationFlags::from_bits_truncate((*self.as_raw()).flags) }
    }

    #[inline]
    pub fn name(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.name_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn name_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn value(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.value_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn value_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).value.as_ref().map(|s| CStr::from_ptr(s)) }
    }
}

#[derive(Debug, Clone)]
pub struct SignatureNotations<'a, T: 'a> {
    current: Option<SignatureNotation<'a, T>>,
    left: Option<usize>,
}

impl<'a, T> SignatureNotations<'a, T> {
    pub unsafe fn from_list(first: ffi::gpgme_sig_notation_t) -> Self {
        SignatureNotations {
            current: first.as_mut().map(|r| SignatureNotation::from_raw(r)),
            left: count_list!(first),
        }
    }
}

impl<'a, T> Iterator for SignatureNotations<'a, T> {
    list_iterator!(SignatureNotation<'a, T>, SignatureNotation::from_raw);
}
