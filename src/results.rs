#![allow(trivial_numeric_casts)]
use std::{
    ffi::CStr,
    fmt,
    marker::PhantomData,
    ptr,
    str::Utf8Error,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ffi;
use libc;

use crate::{
    error::return_err, notation::SignatureNotations, Context, Error, HashAlgorithm, ImportFlags,
    KeyAlgorithm, NonNull, OpResult, Result, SignMode, SignatureSummary, Validity,
};

macro_rules! impl_result {
    ($(#[$Attr:meta])* $Name:ident : $T:ty = $Constructor:expr) => {
        $(#[$Attr])*
        pub struct $Name(NonNull<$T>);

        unsafe impl Send for $Name {}
        unsafe impl Sync for $Name {}

        impl Drop for $Name {
            #[inline]
            fn drop(&mut self) {
                unsafe {
                    ffi::gpgme_result_unref(self.as_raw().cast());
                }
            }
        }

        impl Clone for $Name {
            #[inline]
            fn clone(&self) -> Self {
                unsafe {
                    ffi::gpgme_result_ref(self.as_raw().cast());
                    Self::from_raw(self.as_raw())
                }
            }
        }

        unsafe impl OpResult for $Name {
            fn from_context(ctx: &Context) -> Option<Self> {
                unsafe {
                    $Constructor(ctx.as_raw()).as_mut().map(|r| {
                        ffi::gpgme_result_ref(ptr::addr_of_mut!(*r).cast());
                        Self::from_raw(r)
                    })
                }
            }
        }

        impl $Name {
            impl_wrapper!($T);
        }
    };
}

macro_rules! impl_subresult {
    ($(#[$Attr:meta])* $Name:ident : $T:ty, $IterName:ident, $Owner:ty) => {
        $(#[$Attr])*
        #[derive(Copy, Clone)]
        pub struct $Name<'result>(NonNull<$T>, PhantomData<&'result $Owner>);

        unsafe impl Send for $Name<'_> {}
        unsafe impl Sync for $Name<'_> {}

        impl $Name<'_> {
            impl_wrapper!($T, PhantomData);
        }

        impl_list_iterator!(pub struct $IterName($Name: $T));
    };
}

impl_subresult! {
    /// Upstream documentation:
    /// [`gpgme_invalid_key_t`](https://www.gnupg.org/documentation/manuals/gpgme/Crypto-Operations.html#index-gpgme_005finvalid_005fkey_005ft)
    InvalidKey: ffi::gpgme_invalid_key_t, InvalidKeys, ()
}

impl<'a> InvalidKey<'a> {
    #[inline]
    pub fn fingerprint(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.fingerprint_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn fingerprint_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).fpr.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn reason(&self) -> Option<Error> {
        unsafe {
            match Error::new((*self.as_raw()).reason) {
                Error::NO_ERROR => None,
                e => Some(e),
            }
        }
    }
}

impl fmt::Debug for InvalidKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InvalidKey")
            .field("raw", &self.as_raw())
            .field("fingerprint", &self.fingerprint_raw())
            .field("reason", &self.reason())
            .finish()
    }
}

impl_result! {
    /// Upstream documentation:
    /// [`gpgme_keylist_result_t`](https://www.gnupg.org/documentation/manuals/gpgme/Listing-Keys.html#index-gpgme_005fkeylist_005fresult_005ft)
    KeyListResult: ffi::gpgme_keylist_result_t = ffi::gpgme_op_keylist_result
}
impl KeyListResult {
    pub fn is_truncated(&self) -> bool {
        unsafe { (*self.as_raw()).truncated() }
    }
}

impl fmt::Debug for KeyListResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyListResult")
            .field("raw", &self.as_raw())
            .field("truncated", &self.is_truncated())
            .finish()
    }
}

impl_result! {
    /// Upstream documentation:
    /// [`gpgme_genkey_result_t`](https://www.gnupg.org/documentation/manuals/gpgme/Generating-Keys.html#index-gpgme_005fgenkey_005fresult_005ft)
    KeyGenerationResult: ffi::gpgme_genkey_result_t = ffi::gpgme_op_genkey_result
}
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
    pub fn fingerprint(&self) -> Result<&str, Option<Utf8Error>> {
        self.fingerprint_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn fingerprint_raw(&self) -> Option<&CStr> {
        unsafe { (*self.as_raw()).fpr.as_ref().map(|s| CStr::from_ptr(s)) }
    }
}

impl fmt::Debug for KeyGenerationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyGenerationResult")
            .field("raw", &self.as_raw())
            .field("fingerprint", &self.fingerprint_raw())
            .finish()
    }
}

impl_result! {
    /// Upstream documentation:
    /// [`gpgme_import_result_t`](https://www.gnupg.org/documentation/manuals/gpgme/Importing-Keys.html#index-gpgme_005fimport_005fresult_005ft)
    ImportResult: ffi::gpgme_import_result_t = ffi::gpgme_op_import_result
}
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
    pub fn skipped_v3_keys(&self) -> u32 {
        unsafe { (*self.as_raw()).skipped_v3_keys as u32 }
    }

    #[inline]
    pub fn imports(&self) -> Imports<'_> {
        unsafe { Imports::from_list((*self.as_raw()).imports) }
    }
}

impl fmt::Debug for ImportResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl_subresult! {
    /// Upstream documentation:
    /// [`gpgme_import_status_t`](https://www.gnupg.org/documentation/manuals/gpgme/Importing-Keys.html#index-gpgme_005fimport_005fstatus_005ft)
    Import: ffi::gpgme_import_status_t, Imports, ImportResult
}
impl<'result> Import<'result> {
    #[inline]
    pub fn fingerprint(&self) -> Result<&'result str, Option<Utf8Error>> {
        self.fingerprint_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn fingerprint_raw(&self) -> Option<&'result CStr> {
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

impl fmt::Debug for Import<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Import")
            .field("raw", &self.as_raw())
            .field("fingerprint", &self.fingerprint_raw())
            .field("result", &self.result())
            .field("status", &self.status())
            .finish()
    }
}

impl_result! {
    /// Upstream documentation:
    /// [`gpgme_encrypt_result_t`](https://www.gnupg.org/documentation/manuals/gpgme/Encrypting-a-Plaintext.html#index-gpgme_005fencrypt_005fresult_005ft)
    EncryptionResult: ffi::gpgme_encrypt_result_t = ffi::gpgme_op_encrypt_result
}
impl EncryptionResult {
    #[inline]
    pub fn invalid_recipients(&self) -> InvalidKeys<'_> {
        unsafe { InvalidKeys::from_list((*self.as_raw()).invalid_recipients) }
    }
}

impl fmt::Debug for EncryptionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionResult")
            .field("raw", &self.as_raw())
            .field("invalid_recipients", &self.invalid_recipients())
            .finish()
    }
}

impl_result! {
    /// Upstream documentation:
    /// [`gpgme_decrypt_result_t`](https://www.gnupg.org/documentation/manuals/gpgme/Decrypt.html#index-gpgme_005fdecrypt_005fresult_005ft)
    DecryptionResult: ffi::gpgme_decrypt_result_t = ffi::gpgme_op_decrypt_result
}
impl DecryptionResult {
    #[inline]
    pub fn unsupported_algorithm(&self) -> Result<&str, Option<Utf8Error>> {
        self.unsupported_algorithm_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn unsupported_algorithm_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.as_raw())
                .unsupported_algorithm
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn is_wrong_key_usage(&self) -> bool {
        unsafe { (*self.as_raw()).wrong_key_usage() }
    }

    #[inline]
    pub fn is_de_vs(&self) -> bool {
        unsafe { (*self.as_raw()).is_de_vs() }
    }

    #[inline]
    pub fn is_mime(&self) -> bool {
        unsafe { (*self.as_raw()).is_mime() }
    }

    #[inline]
    pub fn is_legacy_cipher_no_mdc(&self) -> bool {
        unsafe { (*self.as_raw()).legacy_cipher_nomdc() }
    }

    #[inline]
    pub fn filename(&self) -> Result<&str, Option<Utf8Error>> {
        self.filename_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn filename_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.as_raw())
                .file_name
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn symmetric_key_algorithm(&self) -> Result<&str, Option<Utf8Error>> {
        self.symmetric_key_algorithm_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn symmetric_key_algorithm_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.as_raw())
                .symkey_algo
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn recipients(&self) -> Recipients<'_> {
        unsafe { Recipients::from_list((*self.as_raw()).recipients) }
    }
}

impl fmt::Debug for DecryptionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptionResult")
            .field("raw", &self.as_raw())
            .field("unsupported_algorithm", &self.unsupported_algorithm_raw())
            .field("wrong_key_usage", &self.is_wrong_key_usage())
            .field("filename", &self.filename_raw())
            .field("recipients", &self.recipients())
            .finish()
    }
}

impl_subresult! {
    /// Upstream documentation:
    /// [`gpgme_recipient_t`](https://www.gnupg.org/documentation/manuals/gpgme/Decrypt.html#index-gpgme_005frecipient_005ft)
    Recipient: ffi::gpgme_recipient_t,
    Recipients,
    DecryptionResult
}
impl<'result> Recipient<'result> {
    #[inline]
    pub fn key_id(&self) -> Result<&'result str, Option<Utf8Error>> {
        self.key_id_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn key_id_raw(&self) -> Option<&'result CStr> {
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

impl fmt::Debug for Recipient<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Recipient")
            .field("raw", &self.as_raw())
            .field("key_id", &self.key_id_raw())
            .field("algorithm", &self.algorithm())
            .field("status", &self.status())
            .finish()
    }
}

impl_result! {
    /// Upstream documentation:
    /// [`gpgme_sign_result_t`](https://www.gnupg.org/documentation/manuals/gpgme/Creating-a-Signature.html#index-gpgme_005fsign_005fresult_005ft)
    SigningResult: ffi::gpgme_sign_result_t = ffi::gpgme_op_sign_result
}
impl SigningResult {
    #[inline]
    pub fn invalid_signers(&self) -> InvalidKeys<'_> {
        unsafe { InvalidKeys::from_list((*self.as_raw()).invalid_signers) }
    }

    #[inline]
    pub fn new_signatures(&self) -> NewSignatures<'_> {
        unsafe { NewSignatures::from_list((*self.as_raw()).signatures) }
    }
}

impl fmt::Debug for SigningResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningResult")
            .field("raw", &self.as_raw())
            .field("invalid_signers", &self.invalid_signers())
            .field("new_signatures", &self.new_signatures())
            .finish()
    }
}

impl_subresult! {
    /// Upstream documentation:
    /// [`gpgme_new_signature_t`](https://www.gnupg.org/documentation/manuals/gpgme/Creating-a-Signature.html#index-gpgme_005fnew_005fsignature_005ft)
    NewSignature: ffi::gpgme_new_signature_t,
    NewSignatures,
    SigningResult
}
impl<'result> NewSignature<'result> {
    #[inline]
    pub fn fingerprint(&self) -> Result<&'result str, Option<Utf8Error>> {
        self.fingerprint_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn fingerprint_raw(&self) -> Option<&'result CStr> {
        unsafe { (*self.as_raw()).fpr.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn creation_time(&self) -> SystemTime {
        let timestamp = unsafe { (*self.as_raw()).timestamp };
        UNIX_EPOCH + Duration::from_secs(timestamp as u64)
    }

    #[inline]
    pub fn mode(&self) -> SignMode {
        unsafe { SignMode::from_raw((*self.as_raw()).typ) }
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
        unsafe { (*self.as_raw()).sig_class.into() }
    }
}

impl fmt::Debug for NewSignature<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl_result! {
    /// Upstream documentation:
    /// [`gpgme_verify_result_t`](https://www.gnupg.org/documentation/manuals/gpgme/Verify.html#index-gpgme_005fverify_005fresult_005ft)
    VerificationResult: ffi::gpgme_verify_result_t = ffi::gpgme_op_verify_result
}
impl VerificationResult {
    #[inline]
    pub fn is_mime(&self) -> bool {
        unsafe { (*self.as_raw()).is_mime() }
    }

    #[inline]
    pub fn filename(&self) -> Result<&str, Option<Utf8Error>> {
        self.filename_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn filename_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.as_raw())
                .file_name
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn signatures(&self) -> Signatures<'_> {
        unsafe { Signatures::from_list((*self.as_raw()).signatures) }
    }
}

impl fmt::Debug for VerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerificationResult")
            .field("raw", &self.as_raw())
            .field("filename", &self.filename_raw())
            .field("signatures", &self.signatures())
            .finish()
    }
}

ffi_enum_wrapper! {
    /// Upstream documentation:
    /// [`gpgme_signature_t`](https://www.gnupg.org/documentation/manuals/gpgme/Verify.html#index-gpgme_005fsignature_005ft)
    pub enum PkaTrust: libc::c_uint {
        Unknown = 0,
        Bad = 1,
        Okay = 2,
    }
}

impl_subresult! {
    /// Upstream documentation:
    /// [`gpgme_signature_t`](https://www.gnupg.org/documentation/manuals/gpgme/Verify.html#index-gpgme_005fsignature_005ft)
    Signature: ffi::gpgme_signature_t,
    Signatures,
    VerificationResult
}
impl<'result> Signature<'result> {
    #[inline]
    pub fn summary(&self) -> SignatureSummary {
        unsafe { SignatureSummary::from_bits_truncate((*self.as_raw()).summary as u32) }
    }

    #[inline]
    pub fn fingerprint(&self) -> Result<&'result str, Option<Utf8Error>> {
        self.fingerprint_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn fingerprint_raw(&self) -> Option<&'result CStr> {
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
    pub fn is_de_vs(&self) -> bool {
        unsafe { (*self.as_raw()).is_de_vs() }
    }

    #[inline]
    pub fn pka_trust(&self) -> PkaTrust {
        unsafe { PkaTrust::from_raw((*self.as_raw()).pka_trust()) }
    }

    #[inline]
    pub fn pka_address(&self) -> Result<&'result str, Option<Utf8Error>> {
        self.pka_address_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn pka_address_raw(&self) -> Option<&'result CStr> {
        unsafe {
            (*self.as_raw())
                .pka_address
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn validity(&self) -> Validity {
        unsafe { Validity::from_raw((*self.as_raw()).validity) }
    }

    #[inline]
    pub fn nonvalidity_reason(&self) -> Option<Error> {
        unsafe {
            match Error::new((*self.as_raw()).validity_reason) {
                Error::NO_ERROR => None,
                e => Some(e),
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
    pub fn policy_url(&self) -> Result<&'result str, Option<Utf8Error>> {
        self.policy_url_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn policy_url_raw(&self) -> Option<&'result CStr> {
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
    pub fn notations(&self) -> SignatureNotations<'result> {
        unsafe { SignatureNotations::from_list((*self.as_raw()).notations) }
    }

    #[inline]
    pub fn key(&self) -> Option<crate::Key> {
        unsafe {
            (*self.as_raw()).key.as_mut().map(|k| {
                ffi::gpgme_key_ref(k);
                crate::Key::from_raw(k)
            })
        }
    }
}

impl fmt::Debug for Signature<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl_result! {
    /// Upstream documentation:
    /// [`gpgme_query_swdb_result_t`](https://www.gnupg.org/documentation/manuals/gpgme/Checking-for-updates.html#index-gpgme_005fquery_005fswdb_005fresult_005ft)
    QuerySwdbResult: ffi::gpgme_query_swdb_result_t = ffi::gpgme_op_query_swdb_result
}
impl QuerySwdbResult {
    #[inline]
    pub fn name(&self) -> Result<&str, Option<Utf8Error>> {
        self.name_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn name_raw(&self) -> Option<&CStr> {
        unsafe { (*self.as_raw()).name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn installed_version(&self) -> Result<&str, Option<Utf8Error>> {
        self.installed_version_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn installed_version_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.as_raw())
                .iversion
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn latest_version(&self) -> Result<&str, Option<Utf8Error>> {
        self.latest_version_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn latest_version_raw(&self) -> Option<&CStr> {
        unsafe { (*self.as_raw()).version.as_ref().map(|s| CStr::from_ptr(s)) }
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
