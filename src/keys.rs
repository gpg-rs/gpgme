use std::fmt;
use std::marker::PhantomData;

use ffi;

use {Protocol, Validity, Wrapper};
use error::Error;
use ops::KeyListMode;
use notation::SignatureNotationIter;
use utils;

enum_wrapper! {
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
    }
}

impl KeyAlgorithm {
    pub fn name(&self) -> Option<&str> {
        unsafe {
            utils::from_cstr(ffi::gpgme_pubkey_algo_name(self.0))
        }
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name().unwrap_or("Unknown"))
    }
}

enum_wrapper! {
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
    pub fn name(&self) -> Option<&str> {
        unsafe {
            utils::from_cstr(ffi::gpgme_hash_algo_name(self.0))
        }
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

    pub fn id(&self) -> Option<&str> {
        self.primary_key().and_then(|k| k.id())
    }

    pub fn fingerprint(&self) -> Option<&str> {
        self.primary_key().and_then(|k| k.fingerprint())
    }

    pub fn key_list_mode(&self) -> KeyListMode {
        unsafe {
            KeyListMode::from_bits_truncate((*self.raw).keylist_mode)
        }
    }

    pub fn protocol(&self) -> Protocol {
        unsafe {
            Protocol::from_raw((*self.raw).protocol)
        }
    }

    pub fn owner_trust(&self) -> Validity {
        unsafe {
            Validity::from_raw((*self.raw).owner_trust)
        }
    }

    pub fn issuer_serial(&self) -> Option<&str> {
        unsafe {
            utils::from_cstr((*self.raw).issuer_serial)
        }
    }

    pub fn issuer_name(&self) -> Option<&str> {
        unsafe {
            utils::from_cstr((*self.raw).issuer_name)
        }
    }

    pub fn chain_id(&self) -> Option<&str> {
        unsafe {
            utils::from_cstr((*self.raw).chain_id)
        }
    }

    pub fn primary_key(&self) -> Option<SubKey> {
        self.subkeys().next()
    }

    pub fn user_ids(&self) -> UserIdIter {
        unsafe {
            UserIdIter::from_list((*self.raw).uids)
        }
    }

    pub fn subkeys(&self) -> SubKeyIter {
        unsafe {
            SubKeyIter::from_list((*self.raw).subkeys)
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SubKey<'a> {
    raw: ffi::gpgme_subkey_t,
    phantom: PhantomData<&'a Key>,
}

impl<'a> SubKey<'a> {
    pub unsafe fn from_raw<'b>(raw: ffi::gpgme_subkey_t) -> SubKey<'b> {
        SubKey { raw: raw, phantom: PhantomData }
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

    pub fn id(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).keyid)
        }
    }

    pub fn fingerprint(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).fpr)
        }
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        unsafe {
            KeyAlgorithm::from_raw((*self.raw).pubkey_algo)
        }
    }

    pub fn length(&self) -> usize {
        unsafe {
            (*self.raw).length as usize
        }
    }

    pub fn timestamp(&self) -> Option<i64> {
        let timestamp = unsafe {
            (*self.raw).timestamp
        };
        if timestamp > 0 {
            Some(timestamp)
        } else {
            None
        }
    }

    pub fn expires(&self) -> Option<i64> {
        let expires = unsafe {
            (*self.raw).expires
        };
        if expires > 0 {
            Some(expires)
        } else {
            None
        }
    }

    pub fn card_number(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).card_number)
        }
    }

    pub fn curve(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).curve)
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SubKeyIter<'a> {
    current: ffi::gpgme_subkey_t,
    phantom: PhantomData<&'a Key>,
}

impl<'a> SubKeyIter<'a> {
    pub unsafe fn from_list<'b>(raw: ffi::gpgme_subkey_t) -> SubKeyIter<'b> {
        SubKeyIter { current: raw, phantom: PhantomData }
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
        UserId { raw: raw, phantom: PhantomData }
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

    pub fn uid(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).uid)
        }
    }

    pub fn name(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).name)
        }
    }

    pub fn email(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).email)
        }
    }

    pub fn comment(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).comment)
        }
    }

    pub fn validity(&self) -> Validity {
        unsafe {
            Validity::from_raw((*self.raw).validity)
        }
    }

    pub fn signatures(&self) -> KeySignatureIter {
        unsafe {
            KeySignatureIter::from_list((*self.raw).signatures)
        }
    }
}

impl<'a> fmt::Display for UserId<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.uid().unwrap_or(""))
    }
}

#[derive(Debug, Copy, Clone)]
pub struct UserIdIter<'a> {
    current: ffi::gpgme_user_id_t,
    phantom: PhantomData<&'a Key>,
}

impl<'a> UserIdIter<'a> {
    pub unsafe fn from_list<'b>(raw: ffi::gpgme_user_id_t) -> UserIdIter<'b> {
        UserIdIter { current: raw, phantom: PhantomData }
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
        KeySignature { raw: raw, phantom: PhantomData }
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

    pub fn key_id(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).keyid)
        }
    }

    pub fn uid(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).uid)
        }
    }

    pub fn name(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).name)
        }
    }

    pub fn email(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).email)
        }
    }

    pub fn comment(&self) -> Option<&'a str> {
        unsafe {
            utils::from_cstr((*self.raw).comment)
        }
    }

    pub fn timestamp(&self) -> Option<i64> {
        let timestamp = unsafe {
            (*self.raw).timestamp
        };
        if timestamp > 0 {
            Some(timestamp)
        } else {
            None
        }
    }

    pub fn expires(&self) -> Option<i64> {
        let expires = unsafe {
            (*self.raw).expires
        };
        if expires > 0 {
            Some(expires)
        } else {
            None
        }
    }

    pub fn key_algorithm(&self) -> KeyAlgorithm {
        unsafe {
            KeyAlgorithm::from_raw((*self.raw).pubkey_algo)
        }
    }

    pub fn class(&self) -> u32 {
        unsafe { (*self.raw).sig_class as u32 }
    }

    pub fn status(&self) -> Error {
        unsafe { Error::new((*self.raw).status) }
    }

    pub fn notations(&self) -> SignatureNotationIter<'a, Key> {
        unsafe {
            SignatureNotationIter::from_list((*self.raw).notations)
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct KeySignatureIter<'a> {
    current: ffi::gpgme_key_sig_t,
    phantom: PhantomData<&'a Key>,
}

impl<'a> KeySignatureIter<'a> {
    pub unsafe fn from_list<'b>(raw: ffi::gpgme_key_sig_t) -> KeySignatureIter<'b> {
        KeySignatureIter { current: raw, phantom: PhantomData }
    }
}

impl<'a> Iterator for KeySignatureIter<'a> {
    list_iterator!(KeySignature<'a>, KeySignature::from_raw);
}
