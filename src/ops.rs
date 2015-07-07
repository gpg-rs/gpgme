use std::marker::PhantomData;

use libc;
use ffi;

use {Validity, Wrapper};
use error::{self, Error, Result};
use context::Context;
use keys::{KeyAlgorithm, HashAlgorithm};
use notation::SignatureNotationIter;
use utils;

pub unsafe trait OpResult: Clone + Wrapper {
    fn from_context(ctx: &Context) -> Option<Self>;
}

macro_rules! impl_result {
    ($Name:ident: $T:ty = $Constructor:path) => {
        #[derive(Debug)]
        pub struct $Name {
            raw: $T,
        }

        impl Drop for $Name {
            fn drop(&mut self) {
                unsafe {
                    ffi::gpgme_result_unref(self.raw as *mut libc::c_void);
                }
            }
        }

        impl Clone for $Name {
            fn clone(&self) -> $Name {
                unsafe {
                    ffi::gpgme_result_ref(self.raw as *mut libc::c_void);
                    $Name { raw: self.raw }
                }
            }
        }

        unsafe impl Wrapper for $Name {
            type Raw = $T;

            unsafe fn from_raw(raw: $T) -> $Name {
                $Name { raw: raw }
            }

            fn as_raw(&self) -> $T {
                self.raw
            }
        }

        unsafe impl OpResult for $Name {
            fn from_context(ctx: &Context) -> Option<$Name> {
                unsafe {
                    let result = $Constructor(ctx.as_raw());
                    if !result.is_null() {
                        ffi::gpgme_result_ref(result as *mut libc::c_void);
                        Some($Name::from_raw(result))
                    } else {
                        None
                    }
                }
            }
        }
    };
}

macro_rules! impl_subresult {
    ($Name:ident: $T:ty, $IterName:ident, $Owner:ty) => {
        #[derive(Debug, Copy, Clone)]
        pub struct $Name<'a> {
            raw: $T,
            phantom: PhantomData<&'a $Owner>,
        }

        impl<'a> $Name<'a> {
            pub unsafe fn from_raw<'b>(raw: $T) -> $Name<'b> {
                $Name { raw: raw, phantom: PhantomData }
            }

            pub fn raw(&self) -> $T {
                self.raw
            }
        }

        #[derive(Debug, Copy, Clone)]
        pub struct $IterName<'a> {
            current: $T,
            phantom: PhantomData<&'a $Owner>,
        }

        impl<'a> $IterName<'a> {
            pub fn from_list<'b>(first: $T) -> $IterName<'b> {
                $IterName { current: first, phantom: PhantomData }
            }
        }

        impl<'a> Iterator for $IterName<'a> {
            list_iterator!($Name<'a>, $Name::from_raw);
        }
    };
}

#[derive(Debug, Copy, Clone)]
pub struct InvalidKey<'a, T: 'a> {
    owner: &'a T,
    raw: ffi::gpgme_invalid_key_t,
}

impl<'a, T> InvalidKey<'a, T> {
    pub unsafe fn from_raw<'b>(owner: &'b T, raw: ffi::gpgme_invalid_key_t) -> InvalidKey<'b, T> {
        InvalidKey { owner: owner, raw: raw }
    }

    pub unsafe fn raw(&self) -> ffi::gpgme_invalid_key_t {
        self.raw
    }

    pub fn fingerprint(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).fpr)
        }
    }

    pub fn reason(&self) -> Option<Error> {
        unsafe {
            let reason = (*self.raw).reason;
            if reason != error::GPG_ERR_NO_ERROR {
                Some(Error::new(reason))
            } else {
                None
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct InvalidKeyIter<'a, T: 'a> {
    owner: &'a T,
    current: ffi::gpgme_invalid_key_t,
}

impl<'a, T> InvalidKeyIter<'a, T> {
    pub unsafe fn from_list<'b>(owner: &'b T, first: ffi::gpgme_invalid_key_t) -> InvalidKeyIter<'b, T> {
        InvalidKeyIter { owner: owner, current: first }
    }
}

impl<'a, T> Iterator for InvalidKeyIter<'a, T> {
    type Item = InvalidKey<'a, T>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current;
        if !current.is_null() {
            unsafe {
                self.current = (*current).next;
                Some(InvalidKey::from_raw(self.owner, current))
            }
        } else {
            None
        }
    }
}

bitflags! {
    flags KeyListMode: ffi::gpgme_keylist_mode_t {
        const KEY_LIST_MODE_LOCAL = ffi::GPGME_KEYLIST_MODE_LOCAL,
        const KEY_LIST_MODE_EXTERN = ffi::GPGME_KEYLIST_MODE_EXTERN,
        const KEY_LIST_MODE_SIGS = ffi::GPGME_KEYLIST_MODE_SIGS,
        const KEY_LIST_MODE_SIG_NOTATIONS = ffi::GPGME_KEYLIST_MODE_SIG_NOTATIONS,
        const KEY_LIST_MODE_EPHEMERAL = ffi::GPGME_KEYLIST_MODE_EPHEMERAL,
        const KEY_LIST_MODE_VALIDATE = ffi::GPGME_KEYLIST_MODE_VALIDATE,
    }
}

impl_result!(KeyListResult: ffi::gpgme_keylist_result_t = ffi::gpgme_op_keylist_result);
impl KeyListResult {
    pub fn truncated(&self) -> bool {
        unsafe { (*self.raw).truncated() }
    }
}

impl_result!(KeyGenerateResult: ffi::gpgme_genkey_result_t = ffi::gpgme_op_genkey_result);
impl KeyGenerateResult {
    pub fn has_primary_key(&self) -> bool {
        unsafe { (*self.raw).primary() }
    }

    pub fn has_sub_key(&self) -> bool {
        unsafe { (*self.raw).sub() }
    }

    pub fn fingerprint(&self) -> Option<&str> {
        unsafe {
            utils::from_cstr((*self.raw).fpr)
        }
    }
}

impl_result!(ImportResult: ffi::gpgme_import_result_t = ffi::gpgme_op_import_result);
impl ImportResult {
    pub fn considered(&self) -> u32 {
        unsafe { (*self.raw).considered as u32 }
    }

    pub fn no_user_id(&self) -> u32 {
        unsafe { (*self.raw).no_user_id as u32 }
    }

    pub fn imported(&self) -> u32 {
        unsafe { (*self.raw).imported as u32 }
    }

    pub fn imported_rsa(&self) -> u32 {
        unsafe { (*self.raw).imported_rsa as u32 }
    }

    pub fn unchanged(&self) -> u32 {
        unsafe { (*self.raw).unchanged as u32 }
    }

    pub fn new_user_ids(&self) -> u32 {
        unsafe { (*self.raw).new_user_ids as u32 }
    }

    pub fn new_subkeys(&self) -> u32 {
        unsafe { (*self.raw).new_sub_keys as u32 }
    }

    pub fn new_signatures(&self) -> u32 {
        unsafe { (*self.raw).new_signatures as u32 }
    }

    pub fn new_revocations(&self) -> u32 {
        unsafe { (*self.raw).new_revocations as u32 }
    }

    pub fn secret_read(&self) -> u32 {
        unsafe { (*self.raw).secret_read as u32 }
    }

    pub fn secret_imported(&self) -> u32 {
        unsafe { (*self.raw).secret_imported as u32 }
    }

    pub fn secret_unchanged(&self) -> u32 {
        unsafe { (*self.raw).secret_unchanged as u32 }
    }

    pub fn not_imported(&self) -> u32 {
        unsafe { (*self.raw).not_imported as u32 }
    }

    pub fn imports(&self) -> ImportStatusIter {
        unsafe {
            ImportStatusIter::from_list((*self.raw).imports)
        }
    }
}

bitflags! {
    flags ImportFlags: libc::c_uint {
        const IMPORT_NEW = ffi::GPGME_IMPORT_NEW,
        const IMPORT_UID = ffi::GPGME_IMPORT_UID,
        const IMPORT_SIG = ffi::GPGME_IMPORT_SIG,
        const IMPORT_SUBKEY = ffi::GPGME_IMPORT_SUBKEY,
        const IMPORT_SECRET = ffi::GPGME_IMPORT_SECRET,
    }
}

impl_subresult!(ImportStatus: ffi::gpgme_import_status_t, ImportStatusIter, ImportResult);
impl<'a> ImportStatus<'a> {
    pub fn fingerprint(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).fpr)
        }
    }

    pub fn result(&self) -> Result<()> {
        unsafe {
            return_err!((*self.raw).result);
            Ok(())
        }
    }

    pub fn status(&self) -> ImportFlags {
        unsafe {
            ImportFlags::from_bits_truncate((*self.raw).status)
        }
    }
}

bitflags! {
    flags ExportMode: ffi::gpgme_export_mode_t {
        const EXPORT_EXTERN = ffi::GPGME_EXPORT_MODE_EXTERN,
        const EXPORT_MINIMAL = ffi::GPGME_EXPORT_MODE_MINIMAL,
    }
}

bitflags! {
    flags EncryptFlags: ffi::gpgme_encrypt_flags_t {
        const ENCRYPT_ALWAYS_TRUST = ffi::GPGME_ENCRYPT_ALWAYS_TRUST,
        const ENCRYPT_NO_ENCRYPT_TO = ffi::GPGME_ENCRYPT_NO_ENCRYPT_TO,
        const ENCRYPT_PREPARE = ffi::GPGME_ENCRYPT_PREPARE,
        const ENCRYPT_EXPECT_SIGN = ffi::GPGME_ENCRYPT_EXPECT_SIGN,
    }
}

impl_result!(EncryptResult: ffi::gpgme_encrypt_result_t = ffi::gpgme_op_encrypt_result);
impl EncryptResult {
    pub fn invalid_recipients(&self) -> InvalidKeyIter<EncryptResult> {
        unsafe {
            InvalidKeyIter::from_list(self, (*self.raw).invalid_recipients)
        }
    }
}

impl_result!(DecryptResult: ffi::gpgme_decrypt_result_t = ffi::gpgme_op_decrypt_result);
impl DecryptResult {
    pub fn filename(&self) -> Option<&str> {
        unsafe {
            utils::from_cstr((*self.raw).file_name)
        }
    }

    pub fn unsupported_algorithm(&self) -> Option<&str> {
        unsafe {
            utils::from_cstr((*self.raw).unsupported_algorithm)
        }
    }

    pub fn wrong_key_usage(&self) -> bool {
        unsafe { (*self.raw).wrong_key_usage() }
    }

    pub fn recipients(&self) -> RecipientIter {
        unsafe {
            RecipientIter::from_list((*self.raw).recipients)
        }
    }
}

impl_subresult!(Recipient: ffi::gpgme_recipient_t, RecipientIter, DecryptResult);
impl<'a> Recipient<'a> {
    pub fn key_id(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).keyid)
        }
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        unsafe {
            KeyAlgorithm::from_raw((*self.raw).pubkey_algo)
        }
    }

    pub fn status(&self) -> Result<()> {
        unsafe {
            return_err!((*self.raw).status);
            Ok(())
        }
    }
}

enum_wrapper! {
    pub enum SignMode: ffi::gpgme_sig_mode_t {
        SIGN_MODE_NORMAL = ffi::GPGME_SIG_MODE_NORMAL,
        SIGN_MODE_DETACH = ffi::GPGME_SIG_MODE_DETACH,
        SIGN_MODE_CLEAR = ffi::GPGME_SIG_MODE_CLEAR,
    }
}

impl_result!(SignResult: ffi::gpgme_sign_result_t = ffi::gpgme_op_sign_result);
impl SignResult {
    pub fn invalid_signers(&self) -> InvalidKeyIter<SignResult> {
        unsafe {
            InvalidKeyIter::from_list(self, (*self.raw).invalid_signers)
        }
    }

    pub fn signatures(&self) -> NewSignatureIter {
        unsafe {
            NewSignatureIter::from_list((*self.raw).signatures)
        }
    }
}

impl_subresult!(NewSignature: ffi::gpgme_new_signature_t, NewSignatureIter, SignResult);
impl<'a> NewSignature<'a> {
    pub fn fingerprint(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).fpr)
        }
    }

    pub fn kind(&self) -> SignMode {
        unsafe {
            SignMode::from_raw((*self.raw).sig_type)
        }
    }

    pub fn class(&self) -> u32 {
        unsafe { (*self.raw).sig_class as u32 }
    }

    pub fn timestamp(&self) -> i64 {
        unsafe { (*self.raw).timestamp as i64 }
    }

    pub fn key_algorithm(&self) -> KeyAlgorithm {
        unsafe {
            KeyAlgorithm::from_raw((*self.raw).pubkey_algo)
        }
    }

    pub fn hash_algorithm(&self) -> HashAlgorithm {
        unsafe {
            HashAlgorithm::from_raw((*self.raw).hash_algo)
        }
    }
}

impl_result!(VerifyResult: ffi::gpgme_verify_result_t = ffi::gpgme_op_verify_result);
impl VerifyResult {
    pub fn filename(&self) -> Option<&str> {
        unsafe {
            utils::from_cstr((*self.raw).file_name)
        }
    }

    pub fn signatures(&self) -> SignatureIter {
        unsafe {
            SignatureIter::from_list((*self.raw).signatures)
        }
    }
}

bitflags! {
    flags SignatureSummary: ffi::gpgme_sigsum_t {
        const SIGNATURE_VALID = ffi::GPGME_SIGSUM_VALID,
        const SIGNATURE_GREEN = ffi::GPGME_SIGSUM_GREEN,
        const SIGNATURE_RED = ffi::GPGME_SIGSUM_RED,
        const SIGNATURE_KEY_REVOKED = ffi::GPGME_SIGSUM_KEY_REVOKED,
        const SIGNATURE_KEY_EXPIRED = ffi::GPGME_SIGSUM_KEY_EXPIRED,
        const SIGNATURE_SIG_EXPIRED = ffi::GPGME_SIGSUM_SIG_EXPIRED,
        const SIGNATURE_KEY_MISSING = ffi::GPGME_SIGSUM_KEY_MISSING,
        const SIGNATURE_CRL_MISSING = ffi::GPGME_SIGSUM_CRL_MISSING,
        const SIGNATURE_CRL_TOO_OLD = ffi::GPGME_SIGSUM_CRL_TOO_OLD,
        const SIGNATURE_BAD_POLICY = ffi::GPGME_SIGSUM_BAD_POLICY,
        const SIGNATURE_SYS_ERROR = ffi::GPGME_SIGSUM_SYS_ERROR,
    }
}

enum_wrapper! {
    pub enum PkaTrust: libc::c_uint {
        PKA_TRUST_NO_INFO = 0,
        PKA_TRUST_BAD = 1,
        PKA_TRUST_OKAY = 2,
    }
}

impl_subresult!(Signature: ffi::gpgme_signature_t, SignatureIter, VerifyResult);
impl<'a> Signature<'a> {
    pub fn fingerprint(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).fpr)
        }
    }

    pub fn chain_model(&self) -> bool {
        unsafe { (*self.raw).chain_model() }
    }

    pub fn pka_trust(&self) -> PkaTrust {
        unsafe {
            PkaTrust::from_raw((*self.raw).pka_trust())
        }
    }

    pub fn wrong_key_usage(&self) -> bool {
        unsafe { (*self.raw).wrong_key_usage() }
    }

    pub fn validity(&self) -> Validity {
        unsafe {
            Validity::from_raw((*self.raw).validity)
        }
    }

    pub fn validity_reason(&self) -> Option<Error> {
        unsafe {
            let reason = (*self.raw).validity_reason;
            if reason != error::GPG_ERR_NO_ERROR {
                Some(Error::new(reason))
            } else {
                None
            }
        }
    }

    pub fn timestamp(&self) -> i64 {
        unsafe { (*self.raw).timestamp as i64 }
    }

    pub fn expires(&self) -> Option<i64> {
        let expires = unsafe {
            (*self.raw).exp_timestamp
        };
        if expires > 0 {
            Some(expires as i64)
        } else {
            None
        }
    }

    pub fn key_algorithm(&self) -> KeyAlgorithm {
        unsafe {
            KeyAlgorithm::from_raw((*self.raw).pubkey_algo)
        }
    }

    pub fn hash_algorithm(&self) -> HashAlgorithm {
        unsafe {
            HashAlgorithm::from_raw((*self.raw).hash_algo)
        }
    }

    pub fn status(&self) -> Result<()> {
        unsafe {
            return_err!((*self.raw).status);
            Ok(())
        }
    }

    pub fn summary(&self) -> SignatureSummary {
        unsafe {
            SignatureSummary::from_bits_truncate((*self.raw).summary as u32)
        }
    }

    pub fn pka_address(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).pka_address)
        }
    }

    pub fn notations(&self) -> SignatureNotationIter<'a, VerifyResult> {
        unsafe {
            SignatureNotationIter::from_list((*self.raw).notations)
        }
    }
}
