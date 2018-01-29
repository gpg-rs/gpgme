#![allow(trivial_numeric_casts)]
use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::str::Utf8Error;

use ffi;

use SignatureNotationFlags;
use utils::NonNull;

#[derive(Copy, Clone)]
pub struct SignatureNotation<'a>(NonNull<ffi::gpgme_sig_notation_t>, PhantomData<&'a ()>);

unsafe impl<'a> Send for SignatureNotation<'a> {}
unsafe impl<'a> Sync for SignatureNotation<'a> {}

impl<'a> SignatureNotation<'a> {
    impl_wrapper!(SignatureNotation(ffi::gpgme_sig_notation_t), PhantomData);

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
        self.name_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn name_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn value(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.value_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn value_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).value.as_ref().map(|s| CStr::from_ptr(s)) }
    }
}

impl<'a> fmt::Debug for SignatureNotation<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SignatureNotation")
            .field("raw", &self.as_raw())
            .field("name", &self.name_raw())
            .field("value", &self.value_raw())
            .field("critical", &self.is_critical())
            .field("human_readable", &self.is_human_readable())
            .finish()
    }
}

impl_list_iterator!(
    SignatureNotations,
    SignatureNotation,
    ffi::gpgme_sig_notation_t
);
