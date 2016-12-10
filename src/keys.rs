use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::str::Utf8Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ffi;

use {Protocol, Validity, Wrapper};
use error::Error;
use ops::KeyListMode;
use notation::SignatureNotationIter;

ffi_enum_wrapper! {
    pub enum KeyAlgorithm: ffi::gpgme_pubkey_algo_t {
        PK_RSA = ffi::GPGME_PK_RSA,
        PK_RSA_ENCRYPT = ffi::GPGME_PK_RSA_E,
        PK_RSA_SIGN = ffi::GPGME_PK_RSA_S,
        PK_ELGAMAL_ENCRYPT = ffi::GPGME_PK_ELG_E,
        PK_DSA = ffi::GPGME_PK_DSA,
        PK_ECC = ffi::GPGME_PK_ECC,
        PK_ELGAMAL = ffi::GPGME_PK_ELG,
        PK_ECDSA = ffi::GPGME_PK_ECDSA,
        PK_ECDH = ffi::GPGME_PK_ECDH,
        PK_EDDSA = ffi::GPGME_PK_EDDSA,
    }
}

impl KeyAlgorithm {
    pub fn name(&self) -> Result<&'static str, Option<Utf8Error>> {
        self.name_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn name_raw(&self) -> Option<&'static CStr> {
        unsafe { ffi::gpgme_pubkey_algo_name(self.0).as_ref().map(|s| CStr::from_ptr(s)) }
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name().unwrap_or("Unknown"))
    }
}

ffi_enum_wrapper! {
    pub enum HashAlgorithm: ffi::gpgme_hash_algo_t {
        HASH_NONE = ffi::GPGME_MD_NONE,
        HASH_MD2 = ffi::GPGME_MD_MD2,
        HASH_MD4 = ffi::GPGME_MD_MD4,
        HASH_MD5 = ffi::GPGME_MD_MD5,
        HASH_SHA1 = ffi::GPGME_MD_SHA1,
        HASH_SHA256 = ffi::GPGME_MD_SHA256,
        HASH_SHA384 = ffi::GPGME_MD_SHA384,
        HASH_SHA512 = ffi::GPGME_MD_SHA512,
        HASH_SHA224 = ffi::GPGME_MD_SHA224,
        HASH_RMD160 = ffi::GPGME_MD_RMD160,
        HASH_TIGER = ffi::GPGME_MD_TIGER,
        HASH_HAVAL = ffi::GPGME_MD_HAVAL,
        HASH_CRC32 = ffi::GPGME_MD_CRC32,
        HASH_CRC32_RFC1510 = ffi::GPGME_MD_CRC32_RFC1510,
        HASH_CRC24_RFC2440 = ffi::GPGME_MD_CRC24_RFC2440,
    }
}

impl HashAlgorithm {
    pub fn name(&self) -> Result<&'static str, Option<Utf8Error>> {
        self.name_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn name_raw(&self) -> Option<&'static CStr> {
        unsafe { ffi::gpgme_hash_algo_name(self.0).as_ref().map(|s| CStr::from_ptr(s)) }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name().unwrap_or("Unknown"))
    }
}

#[derive(Debug)]
pub struct Key {
    raw: ffi::gpgme_key_t,
}

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_key_unref(self.raw);
        }
    }
}

impl Clone for Key {
    fn clone(&self) -> Key {
        unsafe {
            ffi::gpgme_key_ref(self.raw);
            Key { raw: self.raw }
        }
    }
}

unsafe impl Wrapper for Key {
    type Raw = ffi::gpgme_key_t;

    unsafe fn from_raw(raw: ffi::gpgme_key_t) -> Key {
        debug_assert!(!raw.is_null());
        Key { raw: raw }
    }

    fn as_raw(&self) -> ffi::gpgme_key_t {
        self.raw
    }
}

impl Key {
    pub fn is_secret(&self) -> bool {
        unsafe { (*self.raw).secret() }
    }

    pub fn is_qualified(&self) -> bool {
        unsafe { (*self.raw).is_qualified() }
    }

    pub fn is_invalid(&self) -> bool {
        unsafe { (*self.raw).invalid() }
    }

    pub fn is_disabled(&self) -> bool {
        unsafe { (*self.raw).disabled() }
    }

    pub fn is_revoked(&self) -> bool {
        unsafe { (*self.raw).revoked() }
    }

    pub fn is_expired(&self) -> bool {
        unsafe { (*self.raw).expired() }
    }

    pub fn can_encrypt(&self) -> bool {
        unsafe { (*self.raw).can_encrypt() }
    }

    pub fn can_sign(&self) -> bool {
        unsafe { (*self.raw).can_sign() }
    }

    pub fn can_certify(&self) -> bool {
        unsafe { (*self.raw).can_certify() }
    }

    pub fn can_authenticate(&self) -> bool {
        unsafe { (*self.raw).can_authenticate() }
    }

    pub fn id(&self) -> Result<&str, Option<Utf8Error>> {
        self.primary_key().map_or(Err(None), |k| k.id())
    }

    pub fn id_raw(&self) -> Option<&CStr> {
        self.primary_key().and_then(|k| k.id_raw())
    }

    pub fn fingerprint(&self) -> Result<&str, Option<Utf8Error>> {
        self.primary_key().map_or(Err(None), |k| k.fingerprint())
    }

    pub fn fingerprint_raw(&self) -> Option<&CStr> {
        self.primary_key().and_then(|k| k.fingerprint_raw())
    }

    pub fn key_list_mode(&self) -> KeyListMode {
        unsafe { KeyListMode::from_bits_truncate((*self.raw).keylist_mode) }
    }

    pub fn protocol(&self) -> Protocol {
        unsafe { Protocol::from_raw((*self.raw).protocol) }
    }

    pub fn owner_trust(&self) -> Validity {
        unsafe { Validity::from_raw((*self.raw).owner_trust) }
    }

    pub fn issuer_serial(&self) -> Result<&str, Option<Utf8Error>> {
        self.issuer_serial_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn issuer_serial_raw(&self) -> Option<&CStr> {
        unsafe { (*self.raw).issuer_serial.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn issuer_name(&self) -> Result<&str, Option<Utf8Error>> {
        self.issuer_name_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn issuer_name_raw(&self) -> Option<&CStr> {
        unsafe { (*self.raw).issuer_name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn chain_id(&self) -> Result<&str, Option<Utf8Error>> {
        self.chain_id_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn chain_id_raw(&self) -> Option<&CStr> {
        unsafe { (*self.raw).chain_id.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn primary_key(&self) -> Option<SubKey> {
        self.subkeys().next()
    }

    pub fn user_ids(&self) -> UserIdIter {
        unsafe { UserIdIter::from_list((*self.raw).uids) }
    }

    pub fn subkeys(&self) -> SubKeyIter {
        unsafe { SubKeyIter::from_list((*self.raw).subkeys) }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SubKey<'a> {
    raw: ffi::gpgme_subkey_t,
    phantom: PhantomData<&'a Key>,
}

impl<'a> SubKey<'a> {
    pub unsafe fn from_raw<'b>(raw: ffi::gpgme_subkey_t) -> SubKey<'b> {
        debug_assert!(!raw.is_null());
        SubKey {
            raw: raw,
            phantom: PhantomData,
        }
    }

    pub fn raw(&self) -> ffi::gpgme_subkey_t {
        self.raw
    }

    pub fn is_secret(&self) -> bool {
        unsafe { (*self.raw).secret() }
    }

    pub fn is_cardkey(&self) -> bool {
        unsafe { (*self.raw).is_cardkey() }
    }

    pub fn is_qualified(&self) -> bool {
        unsafe { (*self.raw).is_qualified() }
    }

    pub fn is_invalid(&self) -> bool {
        unsafe { (*self.raw).invalid() }
    }

    pub fn is_disabled(&self) -> bool {
        unsafe { (*self.raw).disabled() }
    }

    pub fn is_revoked(&self) -> bool {
        unsafe { (*self.raw).revoked() }
    }

    pub fn is_expired(&self) -> bool {
        unsafe { (*self.raw).expired() }
    }

    pub fn can_encrypt(&self) -> bool {
        unsafe { (*self.raw).can_encrypt() }
    }

    pub fn can_sign(&self) -> bool {
        unsafe { (*self.raw).can_sign() }
    }

    pub fn can_certify(&self) -> bool {
        unsafe { (*self.raw).can_certify() }
    }

    pub fn can_authenticate(&self) -> bool {
        unsafe { (*self.raw).can_authenticate() }
    }

    pub fn id(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.id_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn id_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.raw).keyid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn keygrip(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.keygrip_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn keygrip_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.raw).keygrip.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn fingerprint(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.fingerprint_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn fingerprint_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.raw).fpr.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        unsafe { KeyAlgorithm::from_raw((*self.raw).pubkey_algo) }
    }

    pub fn algorithm_string(&self) -> ::Result<String> {
        unsafe {
            match ffi::gpgme_pubkey_algo_string(self.raw).as_mut() {
                Some(raw) => {
                    let result = CStr::from_ptr(raw).to_str().expect("algorithm string is not valid
                                                                 ascii").to_owned();
                    ffi::gpgme_free(raw as *mut _ as *mut _);
                    Ok(result)
                }
                None => Err(Error::last_os_error()),
            }
        }
    }

    pub fn length(&self) -> usize {
        unsafe { (*self.raw).length as usize }
    }

    pub fn never_expires(&self) -> bool {
        self.expiration_time().is_none()
    }

    pub fn creation_time(&self) -> Option<SystemTime> {
        let timestamp = unsafe { (*self.raw).timestamp };
        if timestamp > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(timestamp as u64))
        } else {
            None
        }
    }

    pub fn expiration_time(&self) -> Option<SystemTime> {
        let expires = unsafe { (*self.raw).expires };
        if expires > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(expires as u64))
        } else {
            None
        }
    }

    pub fn card_number(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.card_number_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn card_number_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.raw).card_number.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn curve(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.curve_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn curve_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.raw).curve.as_ref().map(|s| CStr::from_ptr(s)) }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SubKeyIter<'a> {
    current: ffi::gpgme_subkey_t,
    phantom: PhantomData<&'a Key>,
}

impl<'a> SubKeyIter<'a> {
    pub unsafe fn from_list<'b>(raw: ffi::gpgme_subkey_t) -> SubKeyIter<'b> {
        SubKeyIter {
            current: raw,
            phantom: PhantomData,
        }
    }
}

impl<'a> Iterator for SubKeyIter<'a> {
    list_iterator!(SubKey<'a>, SubKey::from_raw);
}

#[derive(Debug, Copy, Clone)]
pub struct UserId<'a> {
    raw: ffi::gpgme_user_id_t,
    phantom: PhantomData<&'a Key>,
}

impl<'a> UserId<'a> {
    pub unsafe fn from_raw<'b>(raw: ffi::gpgme_user_id_t) -> UserId<'b> {
        debug_assert!(!raw.is_null());
        UserId {
            raw: raw,
            phantom: PhantomData,
        }
    }

    pub fn raw(&self) -> ffi::gpgme_user_id_t {
        self.raw
    }

    pub fn is_revoked(&self) -> bool {
        unsafe { (*self.raw).revoked() }
    }

    pub fn is_invalid(&self) -> bool {
        unsafe { (*self.raw).invalid() }
    }

    pub fn uid(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.uid_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn uid_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.raw).uid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn name(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.name_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn name_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.raw).name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn email(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.email_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn email_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.raw).email.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn comment(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.comment_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn comment_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.raw).comment.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn address(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.address_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn address_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.raw).address.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn validity(&self) -> Validity {
        unsafe { Validity::from_raw((*self.raw).validity) }
    }

    pub fn signatures(&self) -> KeySignatureIter {
        unsafe { KeySignatureIter::from_list((*self.raw).signatures) }
    }

    pub fn tofu_info(&self) -> TofuInfoIter {
        unsafe { TofuInfoIter::from_list((*self.raw).tofu) }
    }
}

impl<'a> fmt::Display for UserId<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let uid = self.uid_raw().map(|s| s.to_string_lossy()).unwrap_or("".into());
        write!(f, "{}", uid)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct UserIdIter<'a> {
    current: ffi::gpgme_user_id_t,
    phantom: PhantomData<&'a Key>,
}

impl<'a> UserIdIter<'a> {
    pub unsafe fn from_list<'b>(raw: ffi::gpgme_user_id_t) -> UserIdIter<'b> {
        UserIdIter {
            current: raw,
            phantom: PhantomData,
        }
    }
}

impl<'a> Iterator for UserIdIter<'a> {
    list_iterator!(UserId<'a>, UserId::from_raw);
}

#[derive(Debug, Copy, Clone)]
pub struct KeySignature<'a> {
    raw: ffi::gpgme_key_sig_t,
    phantom: PhantomData<&'a Key>,
}

impl<'a> KeySignature<'a> {
    pub unsafe fn from_raw<'b>(raw: ffi::gpgme_key_sig_t) -> KeySignature<'b> {
        debug_assert!(!raw.is_null());
        KeySignature {
            raw: raw,
            phantom: PhantomData,
        }
    }

    pub fn raw(&self) -> ffi::gpgme_key_sig_t {
        self.raw
    }

    pub fn is_revoked(&self) -> bool {
        unsafe { (*self.raw).revoked() }
    }

    pub fn is_expired(&self) -> bool {
        unsafe { (*self.raw).expired() }
    }

    pub fn is_invalid(&self) -> bool {
        unsafe { (*self.raw).invalid() }
    }

    pub fn is_exportable(&self) -> bool {
        unsafe { (*self.raw).exportable() }
    }

    pub fn key_id(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.key_id_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn key_id_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.raw).keyid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn uid(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.uid_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn uid_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.raw).uid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn name(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.name_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn name_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.raw).name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn email(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.email_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn email_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.raw).email.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn comment(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.comment_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn comment_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.raw).comment.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn never_expires(&self) -> bool {
        self.expiration_time().is_none()
    }

    pub fn creation_time(&self) -> Option<SystemTime> {
        let timestamp = unsafe { (*self.raw).timestamp };
        if timestamp > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(timestamp as u64))
        } else {
            None
        }
    }

    pub fn expiration_time(&self) -> Option<SystemTime> {
        let expires = unsafe { (*self.raw).expires };
        if expires > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(expires as u64))
        } else {
            None
        }
    }

    pub fn key_algorithm(&self) -> KeyAlgorithm {
        unsafe { KeyAlgorithm::from_raw((*self.raw).pubkey_algo) }
    }

    pub fn class(&self) -> u32 {
        unsafe { (*self.raw).sig_class as u32 }
    }

    pub fn status(&self) -> Error {
        unsafe { Error::new((*self.raw).status) }
    }

    pub fn notations(&self) -> SignatureNotationIter<'a, Key> {
        unsafe { SignatureNotationIter::from_list((*self.raw).notations) }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct KeySignatureIter<'a> {
    current: ffi::gpgme_key_sig_t,
    phantom: PhantomData<&'a Key>,
}

impl<'a> KeySignatureIter<'a> {
    pub unsafe fn from_list<'b>(raw: ffi::gpgme_key_sig_t) -> KeySignatureIter<'b> {
        KeySignatureIter {
            current: raw,
            phantom: PhantomData,
        }
    }
}

impl<'a> Iterator for KeySignatureIter<'a> {
    list_iterator!(KeySignature<'a>, KeySignature::from_raw);
}

ffi_enum_wrapper! {
    pub enum TofuPolicy: ffi::gpgme_tofu_policy_t {
        TOFU_POLICY_NONE = ffi::GPGME_TOFU_POLICY_NONE,
        TOFU_POLICY_AUTO = ffi::GPGME_TOFU_POLICY_AUTO,
        TOFU_POLICY_GOOD = ffi::GPGME_TOFU_POLICY_GOOD,
        TOFU_POLICY_UNKNOWN = ffi::GPGME_TOFU_POLICY_UNKNOWN,
        TOFU_POLICY_BAD = ffi::GPGME_TOFU_POLICY_BAD,
        TOFU_POLICY_ASK = ffi::GPGME_TOFU_POLICY_ASK,
    }
}

pub struct TofuInfo<'a> {
    raw: ffi::gpgme_tofu_info_t,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> TofuInfo<'a> {
    pub unsafe fn from_raw(raw: ffi::gpgme_tofu_info_t) -> Self {
        debug_assert!(!raw.is_null());
        TofuInfo {
            raw: raw,
            _phantom: PhantomData,
        }
    }

    pub fn raw(&self) -> ffi::gpgme_tofu_info_t {
        self.raw
    }

    pub fn validity(&self) -> u32 {
        unsafe { (*self.raw).validity() }
    }

    pub fn policy(&self) -> TofuPolicy {
        unsafe {
            TofuPolicy::from_raw((*self.raw).policy())
        }
    }

    pub fn sign_count(&self) -> u64 {
        unsafe {
            (*self.raw).signcount.into()
        }
    }

    pub fn encr_count(&self) -> u64 {
        unsafe {
            (*self.raw).encrcount.into()
        }
    }

    pub fn sign_first(&self) -> u64 {
        unsafe {
            (*self.raw).signfirst.into()
        }
    }

    pub fn sign_last(&self) -> u64 {
        unsafe {
            (*self.raw).signlast.into()
        }
    }

    pub fn encr_first(&self) -> u64 {
        unsafe {
            (*self.raw).encrfirst.into()
        }
    }

    pub fn encr_last(&self) -> u64 {
        unsafe {
            (*self.raw).encrlast.into()
        }
    }

    pub fn description(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.description_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn description_raw(&self) -> Option<&'a CStr> {
        unsafe {
            (*self.raw).description.as_ref().map(|s| CStr::from_ptr(s))
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct TofuInfoIter<'a> {
    current: ffi::gpgme_tofu_info_t,
    _phantom: PhantomData<&'a Key>,
}

impl<'a> TofuInfoIter<'a> {
    pub unsafe fn from_list<'b>(raw: ffi::gpgme_tofu_info_t) -> TofuInfoIter<'b> {
        TofuInfoIter {
            current: raw,
            _phantom: PhantomData,
        }
    }
}

impl<'a> Iterator for TofuInfoIter<'a> {
    list_iterator!(TofuInfo<'a>, TofuInfo::from_raw);
}
