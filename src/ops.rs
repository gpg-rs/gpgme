use std::ffi::CStr;
use std::marker::PhantomData;
use std::str;

use libc;

use enum_primitive::FromPrimitive;

use gpgme_sys as sys;

use error::Error;
use keys::{KeyAlgorithm, HashAlgorithm, Validity};

macro_rules! impl_result {
    ($Name:ident: $T:ty) => {
        #[derive(Debug)]
        pub struct $Name {
            raw: $T,
        }

        impl $Name {
            pub unsafe fn from_raw(raw: $T) -> $Name {
                $Name { raw: raw }
            }

            pub unsafe fn raw(&self) -> $T {
                self.raw
            }
        }

        impl Drop for $Name {
            fn drop(&mut self) {
                unsafe {
                    sys::gpgme_result_unref(self.raw as *mut libc::c_void);
                }
            }
        }

        impl Clone for $Name {
            fn clone(&self) -> $Name {
                unsafe {
                    sys::gpgme_result_ref(self.raw as *mut libc::c_void);
                    $Name { raw: self.raw }
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

            pub unsafe fn raw(&self) -> $T {
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
            type Item = $Name<'a>;

            fn next(&mut self) -> Option<Self::Item> {
                let current = self.current;
                if !current.is_null() {
                    unsafe {
                        self.current = (*current).next;
                        Some($Name::from_raw(current))
                    }
                } else {
                    None
                }
            }
        }
    };
}

#[derive(Debug, Copy, Clone)]
pub struct InvalidKey<'a, T: 'a> {
    owner: &'a T,
    raw: sys::gpgme_invalid_key_t,
}

impl<'a, T> InvalidKey<'a, T> {
    pub unsafe fn from_raw<'b>(owner: &'b T, raw: sys::gpgme_invalid_key_t) -> InvalidKey<'b, T> {
        InvalidKey { owner: owner, raw: raw }
    }

    pub unsafe fn raw(&self) -> sys::gpgme_invalid_key_t {
        self.raw
    }

    pub fn fingerprint(&self) -> &'a str {
        unsafe {
            str::from_utf8(CStr::from_ptr((*self.raw).fpr).to_bytes()).unwrap()
        }
    }

    pub fn reason(&self) -> Error {
        unsafe { Error::new((*self.raw).reason) }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct InvalidKeyIter<'a, T: 'a> {
    owner: &'a T,
    current: sys::gpgme_invalid_key_t,
}

impl<'a, T> InvalidKeyIter<'a, T> {
    pub unsafe fn from_list<'b>(owner: &'b T, first: sys::gpgme_invalid_key_t) -> InvalidKeyIter<'b, T> {
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
    flags KeyListMode: sys::gpgme_keylist_mode_t {
        const KEY_LIST_MODE_LOCAL = sys::GPGME_KEYLIST_MODE_LOCAL,
        const KEY_LIST_MODE_EXTERN = sys::GPGME_KEYLIST_MODE_EXTERN,
        const KEY_LIST_MODE_SIGS = sys::GPGME_KEYLIST_MODE_SIGS,
        const KEY_LIST_MODE_SIG_NOTATIONS = sys::GPGME_KEYLIST_MODE_SIG_NOTATIONS,
        const KEY_LIST_MODE_EPHEMERAL = sys::GPGME_KEYLIST_MODE_EPHEMERAL,
        const KEY_LIST_MODE_VALIDATE = sys::GPGME_KEYLIST_MODE_VALIDATE,
    }
}

impl_result!(KeyListResult: sys::gpgme_keylist_result_t);
impl KeyListResult {
    pub fn truncated(&self) -> bool {
        unsafe { (*self.raw).truncated() }
    }
}

impl_result!(KeyGenerateResult: sys::gpgme_genkey_result_t);
impl KeyGenerateResult {
    pub fn has_primary_key(&self) -> bool {
        unsafe { (*self.raw).primary() }
    }

    pub fn has_sub_key(&self) -> bool {
        unsafe { (*self.raw).sub() }
    }

    pub fn fingerprint(&self) -> Option<&str> {
        unsafe {
            let fpr = (*self.raw).fpr;
            if !fpr.is_null() {
                str::from_utf8(CStr::from_ptr(fpr).to_bytes()).ok()
            } else {
                None
            }
        }
    }
}

impl_result!(ImportResult: sys::gpgme_import_result_t);
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

    pub fn new_sub_keys(&self) -> u32 {
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
        const IMPORT_NEW = sys::GPGME_IMPORT_NEW,
        const IMPORT_UID = sys::GPGME_IMPORT_UID,
        const IMPORT_SIG = sys::GPGME_IMPORT_SIG,
        const IMPORT_SUBKEY = sys::GPGME_IMPORT_SUBKEY,
        const IMPORT_SECRET = sys::GPGME_IMPORT_SECRET,
    }
}

impl_subresult!(ImportStatus: sys::gpgme_import_status_t, ImportStatusIter, ImportResult);
impl<'a> ImportStatus<'a> {
    pub fn fingerprint(&self) -> &'a str {
        unsafe {
            str::from_utf8(CStr::from_ptr((*self.raw).fpr).to_bytes()).unwrap()
        }
    }

    pub fn result(&self) -> Error {
        unsafe { Error::new((*self.raw).result) }
    }

    pub fn status(&self) -> ImportFlags {
        unsafe {
            ImportFlags::from_bits_truncate((*self.raw).status)
        }
    }
}

bitflags! {
    flags ExportMode: sys::gpgme_export_mode_t {
        const EXPORT_EXTERN = sys::GPGME_EXPORT_MODE_EXTERN,
        const EXPORT_MINIMAL = sys::GPGME_EXPORT_MODE_MINIMAL,
    }
}

bitflags! {
    flags EncryptFlags: sys::gpgme_encrypt_flags_t {
        const ENCRYPT_ALWAYS_TRUST = sys::GPGME_ENCRYPT_ALWAYS_TRUST,
        const ENCRYPT_NO_ENCRYPT_TO = sys::GPGME_ENCRYPT_NO_ENCRYPT_TO,
        const ENCRYPT_PREPARE = sys::GPGME_ENCRYPT_PREPARE,
        const ENCRYPT_EXPECT_SIGN = sys::GPGME_ENCRYPT_EXPECT_SIGN,
    }
}

impl_result!(EncryptResult: sys::gpgme_encrypt_result_t);
impl EncryptResult {
    pub fn invalid_recipients<'a>(&'a self) -> InvalidKeyIter<'a, EncryptResult> {
        unsafe {
            InvalidKeyIter::from_list(self, (*self.raw).invalid_recipients)
        }
    }
}

impl_result!(DecryptResult: sys::gpgme_decrypt_result_t);
impl DecryptResult {
    pub fn filename(&self) -> Option<&str> {
        unsafe {
            let name = (*self.raw).file_name;
            if !name.is_null() {
                str::from_utf8(CStr::from_ptr(name).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    pub fn unsupported_algorithm(&self) -> Option<&str> {
        unsafe {
            let desc = (*self.raw).unsupported_algorithm;
            if desc.is_null() {
                return None;
            }
            str::from_utf8(CStr::from_ptr(desc).to_bytes()).ok()
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

impl_subresult!(Recipient: sys::gpgme_recipient_t, RecipientIter, DecryptResult);
impl<'a> Recipient<'a> {
    pub fn key_id(&self) -> &str {
        unsafe {
            str::from_utf8(CStr::from_ptr((*self.raw).keyid).to_bytes()).unwrap()
        }
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        unsafe {
            KeyAlgorithm::from_u32((*self.raw).pubkey_algo as u32).unwrap_or(KeyAlgorithm::Unknown)
        }
    }

    pub fn status(&self) -> Error {
        unsafe {
            Error::new((*self.raw).status)
        }
    }
}

enum_from_primitive! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub enum SignMode {
        Unknown = -1,
        Normal = 0,
        Detach = 1,
        Clear = 2,
    }
}

impl_result!(SignResult: sys::gpgme_sign_result_t);
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

impl_subresult!(NewSignature: sys::gpgme_new_signature_t, NewSignatureIter, SignResult);
impl<'a> NewSignature<'a> {
    pub fn fingerprint(&self) -> Option<&'a str> {
        unsafe {
            let fpr = (*self.raw).fpr;
            if !fpr.is_null() {
                str::from_utf8(CStr::from_ptr(fpr).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    pub fn kind(&self) -> SignMode {
        unsafe {
            SignMode::from_u32((*self.raw).sig_type as u32).unwrap_or(SignMode::Unknown)
        }
    }

    pub fn timestamp(&self) -> i64 {
        unsafe { (*self.raw).timestamp as i64 }
    }

    pub fn key_algorithm(&self) -> KeyAlgorithm {
        unsafe {
            KeyAlgorithm::from_u32((*self.raw).pubkey_algo as u32).unwrap_or(KeyAlgorithm::Unknown)
        }
    }

    pub fn hash_algorithm(&self) -> HashAlgorithm {
        unsafe {
            HashAlgorithm::from_u32((*self.raw).hash_algo as u32).unwrap_or(HashAlgorithm::Unknown)
        }
    }
}

impl_result!(VerifyResult: sys::gpgme_verify_result_t);
impl VerifyResult {
    pub fn filename(&self) -> Option<&str> {
        unsafe {
            let name = (*self.raw).file_name;
            if !name.is_null() {
                str::from_utf8(CStr::from_ptr(name).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    pub fn signatures(&self) -> SignatureIter {
        unsafe {
            SignatureIter::from_list((*self.raw).signatures)
        }
    }
}

bitflags! {
    flags SignatureSummary: sys::gpgme_sigsum_t {
        const SIGNATURE_VALID = sys::GPGME_SIGSUM_VALID,
        const SIGNATURE_GREEN = sys::GPGME_SIGSUM_GREEN,
        const SIGNATURE_RED = sys::GPGME_SIGSUM_RED,
        const SIGNATURE_KEY_REVOKED = sys::GPGME_SIGSUM_KEY_REVOKED,
        const SIGNATURE_KEY_EXPIRED = sys::GPGME_SIGSUM_KEY_EXPIRED,
        const SIGNATURE_SIG_EXPIRED = sys::GPGME_SIGSUM_SIG_EXPIRED,
        const SIGNATURE_KEY_MISSING = sys::GPGME_SIGSUM_KEY_MISSING,
        const SIGNATURE_CRL_MISSING = sys::GPGME_SIGSUM_CRL_MISSING,
        const SIGNATURE_CRL_TOO_OLD = sys::GPGME_SIGSUM_CRL_TOO_OLD,
        const SIGNATURE_BAD_POLICY = sys::GPGME_SIGSUM_BAD_POLICY,
        const SIGNATURE_SYS_ERROR = sys::GPGME_SIGSUM_SYS_ERROR,
    }
}

enum_from_primitive! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub enum PkaTrust {
        Unknown = -1,
        NoInfo = 0,
        Bad = 1,
        Okay = 2,
        Reserved = 3,
    }
}

impl_subresult!(Signature: sys::gpgme_signature_t, SignatureIter, VerifyResult);
impl<'a> Signature<'a> {
    pub fn fingerprint(&self) -> Option<&'a str> {
        unsafe {
            let fpr = (*self.raw).fpr;
            if !fpr.is_null() {
                str::from_utf8(CStr::from_ptr(fpr).to_bytes()).ok()
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

    pub fn wrong_key_usage(&self) -> bool {
        unsafe { (*self.raw).wrong_key_usage() }
    }

    pub fn validity(&self) -> Validity {
        unsafe {
            Validity::from_u32((*self.raw).validity as u32).unwrap_or(Validity::Unknown)
        }
    }

    pub fn validity_reason(&self) -> Error {
        unsafe { Error::new((*self.raw).validity_reason) }
    }

    pub fn key_algorithm(&self) -> KeyAlgorithm {
        unsafe {
            KeyAlgorithm::from_u32((*self.raw).pubkey_algo as u32).unwrap_or(KeyAlgorithm::Unknown)
        }
    }

    pub fn hash_algorithm(&self) -> HashAlgorithm {
        unsafe {
            HashAlgorithm::from_u32((*self.raw).hash_algo as u32).unwrap_or(HashAlgorithm::Unknown)
        }
    }

    pub fn status(&self) -> Error {
        unsafe { Error::new((*self.raw).status) }
    }

    pub fn summary(&self) -> SignatureSummary {
        unsafe {
            SignatureSummary::from_bits_truncate((*self.raw).summary as u32)
        }
    }

    pub fn chain_model(&self) -> bool {
        unsafe { (*self.raw).chain_model() }
    }

    pub fn pka_trust(&self) -> PkaTrust {
        unsafe {
            PkaTrust::from_u32((*self.raw).pka_trust() as u32).unwrap_or(PkaTrust::Unknown)
        }
    }

    pub fn pka_address(&self) -> Option<&'a str> {
        unsafe {
            let pka_address = (*self.raw).pka_address;
            if !pka_address.is_null() {
                str::from_utf8(CStr::from_ptr(pka_address).to_bytes()).ok()
            } else {
                None
            }
        }
    }
}
