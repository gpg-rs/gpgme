use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::str::Utf8Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ffi;

ffi_enum_wrapper! {
    pub enum TofuPolicy: ffi::gpgme_tofu_policy_t {
        None = ffi::GPGME_TOFU_POLICY_NONE,
        Auto = ffi::GPGME_TOFU_POLICY_AUTO,
        Good = ffi::GPGME_TOFU_POLICY_GOOD,
        Unknown = ffi::GPGME_TOFU_POLICY_UNKNOWN,
        Bad = ffi::GPGME_TOFU_POLICY_BAD,
        Ask = ffi::GPGME_TOFU_POLICY_ASK,
    }
}

#[derive(Copy, Clone)]
pub struct TofuInfo<'a>(ffi::gpgme_tofu_info_t, PhantomData<&'a ()>);

impl<'a> TofuInfo<'a> {
    impl_wrapper!(@phantom TofuInfo: ffi::gpgme_tofu_info_t);

    #[inline]
    pub fn validity(&self) -> u32 {
        unsafe { (*self.0).validity() }
    }

    #[inline]
    pub fn policy(&self) -> TofuPolicy {
        unsafe { TofuPolicy::from_raw((*self.0).policy()) }
    }

    #[inline]
    pub fn signature_count(&self) -> u64 {
        unsafe { (*self.0).signcount.into() }
    }

    #[inline]
    pub fn encrypted_count(&self) -> u64 {
        unsafe { (*self.0).encrcount.into() }
    }

    #[inline]
    pub fn first_signed(&self) -> Option<SystemTime> {
        let sign_first = unsafe { (*self.0).signfirst };
        if sign_first > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(sign_first.into()))
        } else {
            None
        }
    }

    #[inline]
    pub fn last_signed(&self) -> Option<SystemTime> {
        let sign_last = unsafe { (*self.0).signlast };
        if sign_last > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(sign_last.into()))
        } else {
            None
        }
    }

    #[inline]
    pub fn first_encrypted(&self) -> Option<SystemTime> {
        let encr_first = unsafe { (*self.0).encrfirst };
        if encr_first > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(encr_first.into()))
        } else {
            None
        }
    }

    #[inline]
    pub fn last_encrypted(&self) -> Option<SystemTime> {
        let encr_last = unsafe { (*self.0).encrlast };
        if encr_last > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(encr_last.into()))
        } else {
            None
        }
    }

    #[inline]
    pub fn description(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.description_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn description_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).description.as_ref().map(|s| CStr::from_ptr(s)) }
    }
}

impl<'a> fmt::Debug for TofuInfo<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("TofuInfo")
            .field("desc", &self.description().unwrap_or("<null>"))
            .field("validity", &self.validity())
            .field("policy", &self.policy())
            .field("sign_count", &self.signature_count())
            .field("sign_first", &self.first_signed())
            .field("sign_last", &self.last_signed())
            .field("encr_count", &self.encrypted_count())
            .field("encr_first", &self.first_encrypted())
            .field("encr_last", &self.last_encrypted())
            .field("raw", &self.0)
            .finish()
    }
}
