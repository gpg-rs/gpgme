#![allow(trivial_numeric_casts)]
use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::result;
use std::str::Utf8Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libc;
use ffi;

use {Context, Error, HashAlgorithm, ImportFlags, KeyAlgorithm, NonZero, OpResult, Result,
     SignMode, SignatureSummary, Validity};
use error;
use notation::SignatureNotations;

macro_rules! impl_result {
    ($Name:ident: $T:ty = $Constructor:expr) => {
        pub struct $Name(NonZero<$T>);

        unsafe impl Send for $Name {}
        unsafe impl Sync for $Name {}

        impl Drop for $Name {
            #[inline]
            fn drop(&mut self) {
                unsafe {
                    ffi::gpgme_result_unref(self.as_raw() as *mut libc::c_void);
                }
            }
        }

        impl Clone for $Name {
            #[inline]
            fn clone(&self) -> $Name {
                unsafe {
                    ffi::gpgme_result_ref(self.as_raw() as *mut libc::c_void);
                    $Name(self.0)
                }
            }
        }

        unsafe impl OpResult for $Name {
            fn from_context(ctx: &Context) -> Option<$Name> {
                unsafe {
                    $Constructor(ctx.as_raw()).as_mut().map(|r| {
                        ffi::gpgme_result_ref(r as *mut _ as *mut libc::c_void);
                        $Name::from_raw(r)
                    })
                }
            }
        }

        impl $Name {
            impl_wrapper!($Name: $T);
        }
    };
}

macro_rules! impl_subresult {
    ($Name:ident: $T:ty, $IterName:ident, $Owner:ty) => {
        #[derive(Copy, Clone)]
        pub struct $Name<'a>(NonZero<$T>, PhantomData<&'a $Owner>);

        unsafe impl<'a> Send for $Name<'a> {}
        unsafe impl<'a> Sync for $Name<'a> {}

        impl<'a> $Name<'a> {
            impl_wrapper!(@phantom $Name: $T);
        }

        impl_list_iterator!($IterName, $Name, $T);
    };
}

impl_subresult!(InvalidKey: ffi::gpgme_invalid_key_t, InvalidKeys, ());

impl<'a> InvalidKey<'a> {
    #[inline]
    pub fn fingerprint(&self) -> result::Result<&'a str, Option<Utf8Error>> {
        self.fingerprint_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn fingerprint_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).fpr.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn reason(&self) -> Option<Error> {
        unsafe {
            match (*self.as_raw()).reason {
                error::GPG_ERR_NO_ERROR => None,
                e => Some(Error::new(e)),
            }
        }
    }
}

impl<'a> fmt::Debug for InvalidKey<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("InvalidKey")
            .field("raw", &self.as_raw())
            .field("fingerprint", &self.fingerprint_raw())
            .field("reason", &self.reason())
            .finish()
    }
}

impl_result!(KeyListResult: ffi::gpgme_keylist_result_t = ffi::gpgme_op_keylist_result);
impl KeyListResult {
    pub fn is_truncated(&self) -> bool {
        unsafe { (*self.as_raw()).truncated() }
    }
}

impl fmt::Debug for KeyListResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("KeyListResult")
            .field("raw", &self.as_raw())
            .field("truncated", &self.is_truncated())
            .finish()
    }
}

impl_result!(KeyGenerationResult: ffi::gpgme_genkey_result_t = ffi::gpgme_op_genkey_result);
impl KeyGenerationResult {
    #[inline]
    pub fn has_primary_key(&self) -> bool {
        unsafe { (*self.as_raw()).primary() }
    }

    #[inline]
    pub fn has_sub_key(&self) -> bool {
        unsafe { (*self.as_raw()).sub() }
    }

    #[inline]
    pub fn has_uid(&self) -> bool {
        unsafe { (*self.as_raw()).uid() }
    }

    #[inline]
    pub fn fingerprint(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.fingerprint_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn fingerprint_raw(&self) -> Option<&CStr> {
        unsafe { (*self.as_raw()).fpr.as_ref().map(|s| CStr::from_ptr(s)) }
    }
}

impl<'a> fmt::Debug for KeyGenerationResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("KeyGenerationResult")
            .field("raw", &self.as_raw())
            .field("fingerprint", &self.fingerprint_raw())
            .finish()
    }
}

impl_result!(ImportResult: ffi::gpgme_import_result_t = ffi::gpgme_op_import_result);
impl ImportResult {
    #[inline]
    pub fn considered(&self) -> u32 {
        unsafe { (*self.as_raw()).considered as u32 }
    }

    #[inline]
    pub fn without_user_id(&self) -> u32 {
        unsafe { (*self.as_raw()).no_user_id as u32 }
    }

    #[inline]
    pub fn imported(&self) -> u32 {
        unsafe { (*self.as_raw()).imported as u32 }
    }

    #[inline]
    pub fn imported_rsa(&self) -> u32 {
        unsafe { (*self.as_raw()).imported_rsa as u32 }
    }

    #[inline]
    pub fn unchanged(&self) -> u32 {
        unsafe { (*self.as_raw()).unchanged as u32 }
    }

    #[inline]
    pub fn new_user_ids(&self) -> u32 {
        unsafe { (*self.as_raw()).new_user_ids as u32 }
    }

    #[inline]
    pub fn new_subkeys(&self) -> u32 {
        unsafe { (*self.as_raw()).new_sub_keys as u32 }
    }

    #[inline]
    pub fn new_signatures(&self) -> u32 {
        unsafe { (*self.as_raw()).new_signatures as u32 }
    }

    #[inline]
    pub fn new_revocations(&self) -> u32 {
        unsafe { (*self.as_raw()).new_revocations as u32 }
    }

    #[inline]
    pub fn secret_considered(&self) -> u32 {
        unsafe { (*self.as_raw()).secret_read as u32 }
    }

    #[inline]
    pub fn secret_imported(&self) -> u32 {
        unsafe { (*self.as_raw()).secret_imported as u32 }
    }

    #[inline]
    pub fn secret_unchanged(&self) -> u32 {
        unsafe { (*self.as_raw()).secret_unchanged as u32 }
    }

    #[inline]
    pub fn not_imported(&self) -> u32 {
        unsafe { (*self.as_raw()).not_imported as u32 }
    }

    #[inline]
    pub fn imports(&self) -> Imports {
        unsafe { Imports::from_list((*self.as_raw()).imports) }
    }
}

impl fmt::Debug for ImportResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ImportResult")
            .field("raw", &self.as_raw())
            .field("without_user_id", &self.without_user_id())
            .field("new_user_ids", &self.new_user_ids())
            .field("new_subkeys", &self.new_subkeys())
            .field("new_signatures", &self.new_signatures())
            .field("new_revocations", &self.new_revocations())
            .field("considered", &self.considered())
            .field("imported", &self.imported())
            .field("unchanged", &self.unchanged())
            .field("secret_considered", &self.secret_considered())
            .field("secret_imported", &self.secret_imported())
            .field("secret_unchanged", &self.secret_unchanged())
            .field("not_imported", &self.not_imported())
            .field("imports", &self.imports())
            .finish()
    }
}

impl_subresult!(Import: ffi::gpgme_import_status_t, Imports, ImportResult);
impl<'a> Import<'a> {
    #[inline]
    pub fn fingerprint(&self) -> result::Result<&'a str, Option<Utf8Error>> {
        self.fingerprint_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn fingerprint_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).fpr.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn result(&self) -> Result<()> {
        unsafe {
            return_err!((*self.as_raw()).result);
            Ok(())
        }
    }

    #[inline]
    pub fn status(&self) -> ImportFlags {
        unsafe { ImportFlags::from_bits_truncate((*self.as_raw()).status) }
    }
}

impl<'a> fmt::Debug for Import<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Import")
            .field("raw", &self.as_raw())
            .field("fingerprint", &self.fingerprint_raw())
            .field("result", &self.result())
            .field("status", &self.status())
            .finish()
    }
}

impl_result!(EncryptionResult: ffi::gpgme_encrypt_result_t = ffi::gpgme_op_encrypt_result);
impl EncryptionResult {
    #[inline]
    pub fn invalid_recipients(&self) -> InvalidKeys {
        unsafe { InvalidKeys::from_list((*self.as_raw()).invalid_recipients) }
    }
}

impl fmt::Debug for EncryptionResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("EncryptionResult")
            .field("raw", &self.as_raw())
            .field("invalid_recipients", &self.invalid_recipients())
            .finish()
    }
}

impl_result!(DecryptionResult: ffi::gpgme_decrypt_result_t = ffi::gpgme_op_decrypt_result);
impl DecryptionResult {
    #[inline]
    pub fn unsupported_algorithm(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.unsupported_algorithm_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn unsupported_algorithm_raw(&self) -> Option<&CStr> {
        unsafe { (*self.as_raw()).unsupported_algorithm.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn is_wrong_key_usage(&self) -> bool {
        unsafe { (*self.as_raw()).wrong_key_usage() }
    }

    #[inline]
    pub fn filename(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.filename_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn filename_raw(&self) -> Option<&CStr> {
        unsafe { (*self.as_raw()).file_name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn recipients(&self) -> Recipients {
        unsafe { Recipients::from_list((*self.as_raw()).recipients) }
    }
}

impl fmt::Debug for DecryptionResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("DecryptionResult")
            .field("raw", &self.as_raw())
            .field("unsupported_algorithm", &self.unsupported_algorithm_raw())
            .field("wrong_key_usage", &self.is_wrong_key_usage())
            .field("filename", &self.filename_raw())
            .field("recipients", &self.recipients())
            .finish()
    }
}

impl_subresult!(Recipient: ffi::gpgme_recipient_t,
                Recipients,
                DecryptionResult);
impl<'a> Recipient<'a> {
    #[inline]
    pub fn key_id(&self) -> result::Result<&'a str, Option<Utf8Error>> {
        self.key_id_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn key_id_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).keyid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn algorithm(&self) -> KeyAlgorithm {
        unsafe { KeyAlgorithm::from_raw((*self.as_raw()).pubkey_algo) }
    }

    #[inline]
    pub fn status(&self) -> Result<()> {
        unsafe {
            return_err!((*self.as_raw()).status);
            Ok(())
        }
    }
}

impl<'a> fmt::Debug for Recipient<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Recipient")
            .field("raw", &self.as_raw())
            .field("key_id", &self.key_id_raw())
            .field("algorithm", &self.algorithm())
            .field("status", &self.status())
            .finish()
    }
}

impl_result!(SigningResult: ffi::gpgme_sign_result_t = ffi::gpgme_op_sign_result);
impl SigningResult {
    #[inline]
    pub fn invalid_signers(&self) -> InvalidKeys {
        unsafe { InvalidKeys::from_list((*self.as_raw()).invalid_signers) }
    }

    #[inline]
    pub fn new_signatures(&self) -> NewSignatures {
        unsafe { NewSignatures::from_list((*self.as_raw()).signatures) }
    }
}

impl fmt::Debug for SigningResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SigningResult")
            .field("raw", &self.as_raw())
            .field("invalid_signers", &self.invalid_signers())
            .field("new_signatures", &self.new_signatures())
            .finish()
    }
}

impl_subresult!(NewSignature: ffi::gpgme_new_signature_t,
                NewSignatures,
                SigningResult);
impl<'a> NewSignature<'a> {
    #[inline]
    pub fn fingerprint(&self) -> result::Result<&'a str, Option<Utf8Error>> {
        self.fingerprint_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn fingerprint_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).fpr.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn creation_time(&self) -> SystemTime {
        let timestamp = unsafe { (*self.as_raw()).timestamp };
        UNIX_EPOCH + Duration::from_secs(timestamp as u64)
    }

    #[inline]
    pub fn mode(&self) -> SignMode {
        unsafe { SignMode::from_raw((*self.as_raw()).sig_type) }
    }

    #[inline]
    pub fn key_algorithm(&self) -> KeyAlgorithm {
        unsafe { KeyAlgorithm::from_raw((*self.as_raw()).pubkey_algo) }
    }

    #[inline]
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        unsafe { HashAlgorithm::from_raw((*self.as_raw()).hash_algo) }
    }

    #[inline]
    pub fn signature_class(&self) -> u32 {
        unsafe { (*self.as_raw()).sig_class as u32 }
    }
}

impl<'a> fmt::Debug for NewSignature<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("NewSignature")
            .field("raw", &self.as_raw())
            .field("fingerprint", &self.fingerprint_raw())
            .field("creation_time", &self.creation_time())
            .field("mode", &self.mode())
            .field("key_algorithm", &self.key_algorithm())
            .field("hash_algorithm", &self.hash_algorithm())
            .field("class", &self.signature_class())
            .finish()
    }
}

impl_result!(VerificationResult: ffi::gpgme_verify_result_t = ffi::gpgme_op_verify_result);
impl VerificationResult {
    #[inline]
    pub fn filename(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.filename_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn filename_raw(&self) -> Option<&CStr> {
        unsafe { (*self.as_raw()).file_name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn signatures(&self) -> Signatures {
        unsafe { Signatures::from_list((*self.as_raw()).signatures) }
    }
}

impl fmt::Debug for VerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("VerificationResult")
            .field("raw", &self.as_raw())
            .field("filename", &self.filename_raw())
            .field("signatures", &self.signatures())
            .finish()
    }
}

ffi_enum_wrapper! {
    pub enum PkaTrust: libc::c_uint {
        Unknown = 0,
        Bad = 1,
        Okay = 2,
    }
}

impl_subresult!(Signature: ffi::gpgme_signature_t,
                Signatures,
                VerificationResult);
impl<'a> Signature<'a> {
    #[inline]
    pub fn summary(&self) -> SignatureSummary {
        unsafe { SignatureSummary::from_bits_truncate((*self.as_raw()).summary as u32) }
    }

    #[inline]
    pub fn fingerprint(&self) -> result::Result<&'a str, Option<Utf8Error>> {
        self.fingerprint_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn fingerprint_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).fpr.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn status(&self) -> Result<()> {
        unsafe {
            return_err!((*self.as_raw()).status);
            Ok(())
        }
    }

    #[inline]
    pub fn creation_time(&self) -> Option<SystemTime> {
        let timestamp = unsafe { (*self.as_raw()).timestamp };
        if timestamp > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(timestamp.into()))
        } else {
            None
        }
    }

    #[inline]
    pub fn expiration_time(&self) -> Option<SystemTime> {
        let expires = unsafe { (*self.as_raw()).exp_timestamp };
        if expires > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(expires.into()))
        } else {
            None
        }
    }

    #[inline]
    pub fn never_expires(&self) -> bool {
        self.expiration_time().is_none()
    }

    #[inline]
    pub fn is_wrong_key_usage(&self) -> bool {
        unsafe { (*self.as_raw()).wrong_key_usage() }
    }

    #[inline]
    pub fn verified_by_chain(&self) -> bool {
        unsafe { (*self.as_raw()).chain_model() }
    }

    #[inline]
    pub fn pka_trust(&self) -> PkaTrust {
        unsafe { PkaTrust::from_raw((*self.as_raw()).pka_trust()) }
    }

    #[inline]
    pub fn pka_address(&self) -> result::Result<&'a str, Option<Utf8Error>> {
        self.pka_address_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn pka_address_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).pka_address.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn validity(&self) -> Validity {
        unsafe { Validity::from_raw((*self.as_raw()).validity) }
    }

    #[inline]
    pub fn nonvalidity_reason(&self) -> Option<Error> {
        unsafe {
            let reason = (*self.as_raw()).validity_reason;
            if reason != error::GPG_ERR_NO_ERROR {
                Some(Error::new(reason))
            } else {
                None
            }
        }
    }

    #[inline]
    pub fn key_algorithm(&self) -> KeyAlgorithm {
        unsafe { KeyAlgorithm::from_raw((*self.as_raw()).pubkey_algo) }
    }

    #[inline]
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        unsafe { HashAlgorithm::from_raw((*self.as_raw()).hash_algo) }
    }

    #[inline]
    pub fn policy_url(&self) -> result::Result<&'a str, Option<Utf8Error>> {
        self.policy_url_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn policy_url_raw(&self) -> Option<&'a CStr> {
        unsafe {
            let mut notation = (*self.as_raw()).notations;
            while !notation.is_null() {
                if (*notation).name.is_null() {
                    return (*notation).value.as_ref().map(|s| CStr::from_ptr(s));
                }
                notation = (*notation).next;
            }
            None
        }
    }

    #[inline]
    pub fn notations(&self) -> SignatureNotations<'a> {
        unsafe { SignatureNotations::from_list((*self.as_raw()).notations) }
    }

    #[inline]
    #[cfg(feature = "v1_7_0")]
    pub fn key(&self) -> Option<::Key> {
        unsafe {
            (*self.as_raw()).key.as_mut().map(|k| {
                ffi::gpgme_key_ref(k);
                ::Key::from_raw(k)
            })
        }
    }

    #[inline]
    #[cfg(not(feature = "v1_7_0"))]
    pub fn key(&self) -> Option<::Key> {
        None
    }
}

impl<'a> fmt::Debug for Signature<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Signature")
            .field("raw", &self.as_raw())
            .field("fingerprint", &self.fingerprint_raw())
            .field("creation_time", &self.creation_time())
            .field("expiration_time", &self.expiration_time())
            .field("key_algorithm", &self.key_algorithm())
            .field("hash_algorithm", &self.hash_algorithm())
            .field("summary", &self.summary())
            .field("status", &self.status())
            .field("validity", &self.validity())
            .field("nonvalidity_reason", &self.nonvalidity_reason())
            .field("notations", &self.notations())
            .finish()
    }
}

#[cfg(feature = "v1_8_0")]
impl_result!(QuerySwdbResult: ffi::gpgme_query_swdb_result_t = ffi::gpgme_op_query_swdb_result);
#[cfg(not(feature = "v1_8_0"))]
impl_result!(QuerySwdbResult: ffi::gpgme_query_swdb_result_t = |_| ::std::ptr::null_mut());
impl QuerySwdbResult {
    #[inline]
    pub fn name(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.name_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn name_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.as_raw()).name.as_ref().map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn installed_version(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.installed_version_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn installed_version_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.as_raw()).iversion.as_ref().map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn latest_version(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.latest_version_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn latest_version_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.as_raw()).version.as_ref().map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn creation_time(&self) -> Option<SystemTime> {
        let timestamp = unsafe { (*self.as_raw()).created };
        if timestamp > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(timestamp.into()))
        } else {
            None
        }
    }

    #[inline]
    pub fn retrieval_time(&self) -> Option<SystemTime> {
        let timestamp = unsafe { (*self.as_raw()).retrieved };
        if timestamp > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(timestamp.into()))
        } else {
            None
        }
    }

    #[inline]
    pub fn release_time(&self) -> Option<SystemTime> {
        let timestamp = unsafe { (*self.as_raw()).reldate };
        if timestamp > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(timestamp.into()))
        } else {
            None
        }
    }

    #[inline]
    pub fn has_warning(&self) -> bool {
        unsafe { (*self.as_raw()).warning() }
    }

    #[inline]
    pub fn has_update(&self) -> bool {
        unsafe { (*self.as_raw()).update() }
    }

    #[inline]
    pub fn is_urgent(&self) -> bool {
        unsafe { (*self.as_raw()).urgent() }
    }

    #[inline]
    pub fn has_noinfo(&self) -> bool {
        unsafe { (*self.as_raw()).noinfo() }
    }

    #[inline]
    pub fn is_unknown(&self) -> bool {
        unsafe { (*self.as_raw()).unknown() }
    }

    #[inline]
    pub fn is_too_old(&self) -> bool {
        unsafe { (*self.as_raw()).tooold() }
    }

    #[inline]
    pub fn has_error(&self) -> bool {
        unsafe { (*self.as_raw()).error() }
    }
}

impl fmt::Debug for QuerySwdbResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("QuerySwdbResult")
            .field("raw", &self.as_raw())
            .field("name", &self.name_raw())
            .field("installed_version", &self.installed_version_raw())
            .field("latest_version", &self.latest_version_raw())
            .field("creation_time", &self.creation_time())
            .field("retrieval_time", &self.retrieval_time())
            .field("release_time", &self.release_time())
            .field("has_warning", &self.has_warning())
            .field("has_update", &self.has_update())
            .field("is_urgent", &self.is_urgent())
            .field("has_noinfo", &self.has_noinfo())
            .field("is_unknown", &self.is_unknown())
            .field("is_too_old", &self.is_too_old())
            .field("has_error", &self.has_error())
            .finish()
    }
}
