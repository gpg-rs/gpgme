use std::{ffi::CStr, fmt, marker::PhantomData, str::Utf8Error};

use ffi;

use crate::{utils, NonNull, SignatureNotationFlags};

/// Upstream documentation:
/// [`gpgme_sig_notation_t`](https://www.gnupg.org/documentation/manuals/gpgme/Verify.html#index-gpgme_005fsig_005fnotation_005ft)
#[derive(Copy, Clone)]
pub struct SignatureNotation<'a>(NonNull<ffi::gpgme_sig_notation_t>, PhantomData<&'a ()>);

unsafe impl Send for SignatureNotation<'_> {}
unsafe impl Sync for SignatureNotation<'_> {}

impl<'a> SignatureNotation<'a> {
    impl_wrapper!(ffi::gpgme_sig_notation_t, PhantomData);

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
        unsafe { SignatureNotationFlags::from_bits_retain((*self.as_raw()).flags) }
    }

    #[inline]
    pub fn name(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.name_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn name_raw(&self) -> Option<&'a CStr> {
        unsafe { utils::convert_raw_str((*self.as_raw()).name) }
    }

    #[inline]
    pub fn value(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.value_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn value_raw(&self) -> Option<&'a CStr> {
        unsafe { utils::convert_raw_str((*self.as_raw()).value) }
    }
}

impl fmt::Debug for SignatureNotation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureNotation")
            .field("raw", &self.as_raw())
            .field("name", &self.name_raw())
            .field("value", &self.value_raw())
            .field("critical", &self.is_critical())
            .field("human_readable", &self.is_human_readable())
            .finish()
    }
}

impl_list_iterator!(pub struct SignatureNotations(SignatureNotation: ffi::gpgme_sig_notation_t));
