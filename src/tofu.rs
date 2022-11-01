use std::{
    ffi::CStr,
    fmt,
    marker::PhantomData,
    str::Utf8Error,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ffi;

use crate::NonNull;

ffi_enum_wrapper! {
    /// Upstream documentation:
    /// [`gpgme_tofu_policy_t`](https://www.gnupg.org/documentation/manuals/gpgme/Changing-TOFU-Data.html#index-gpgme_005ftofu_005fpolicy_005ft)
    #[non_exhaustive]
    pub enum TofuPolicy: ffi::gpgme_tofu_policy_t {
        None = ffi::GPGME_TOFU_POLICY_NONE,
        Auto = ffi::GPGME_TOFU_POLICY_AUTO,
        Good = ffi::GPGME_TOFU_POLICY_GOOD,
        Unknown = ffi::GPGME_TOFU_POLICY_UNKNOWN,
        Bad = ffi::GPGME_TOFU_POLICY_BAD,
        Ask = ffi::GPGME_TOFU_POLICY_ASK,
    }
}

/// Upstream documentation:
/// [`gpgme_tofu_info_t`](https://www.gnupg.org/documentation/manuals/gpgme/Key-objects.html#index-gpgme_005ftofu_005finfo_005ft)
#[derive(Copy, Clone)]
pub struct TofuInfo<'a>(NonNull<ffi::gpgme_tofu_info_t>, PhantomData<&'a ()>);

unsafe impl Send for TofuInfo<'_> {}
unsafe impl Sync for TofuInfo<'_> {}

impl<'a> TofuInfo<'a> {
    impl_wrapper!(ffi::gpgme_tofu_info_t, PhantomData);

    #[inline]
    pub fn validity(&self) -> u32 {
        unsafe { (*self.as_raw()).validity() }
    }

    #[inline]
    pub fn policy(&self) -> TofuPolicy {
        unsafe { TofuPolicy::from_raw((*self.as_raw()).policy()) }
    }

    #[inline]
    pub fn signature_count(&self) -> u64 {
        unsafe { (*self.as_raw()).signcount.into() }
    }

    #[inline]
    pub fn encrypted_count(&self) -> u64 {
        unsafe { (*self.as_raw()).encrcount.into() }
    }

    // TODO: Unwrap return value for next major release
    #[inline]
    pub fn first_signed(&self) -> Option<SystemTime> {
        let sign_first = unsafe { (*self.as_raw()).signfirst };
        Some(UNIX_EPOCH + Duration::from_secs(sign_first.into()))
    }

    #[inline]
    pub fn last_signed(&self) -> Option<SystemTime> {
        let sign_last = unsafe { (*self.as_raw()).signlast };
        Some(UNIX_EPOCH + Duration::from_secs(sign_last.into()))
    }

    #[inline]
    pub fn first_encrypted(&self) -> Option<SystemTime> {
        let encr_first = unsafe { (*self.as_raw()).encrfirst };
        Some(UNIX_EPOCH + Duration::from_secs(encr_first.into()))
    }

    #[inline]
    pub fn last_encrypted(&self) -> Option<SystemTime> {
        let encr_last = unsafe { (*self.as_raw()).encrlast };
        Some(UNIX_EPOCH + Duration::from_secs(encr_last.into()))
    }

    #[inline]
    pub fn description(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.description_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn description_raw(&self) -> Option<&'a CStr> {
        unsafe {
            (*self.as_raw())
                .description
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }
}

impl fmt::Debug for TofuInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TofuInfo")
            .field("raw", &self.as_raw())
            .field("description", &self.description_raw())
            .field("validity", &self.validity())
            .field("policy", &self.policy())
            .field("signature_count", &self.signature_count())
            .field("first_signed", &self.first_signed())
            .field("last_signed", &self.last_signed())
            .field("encrypted_count", &self.encrypted_count())
            .field("first_encrypt", &self.first_encrypted())
            .field("last_encrypt", &self.last_encrypted())
            .finish()
    }
}
