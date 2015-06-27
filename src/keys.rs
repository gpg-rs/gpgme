use std::fmt;
use std::marker::PhantomData;

use enum_primitive::FromPrimitive;

use gpgme_sys as sys;

use Protocol;
use error::Error;
use ops::KeyListMode;
use notation::SignatureNotationIter;
use utils;

enum_from_primitive! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub enum Validity {
        Unknown = sys::GPGME_VALIDITY_UNKNOWN as isize,
        Undefined = sys::GPGME_VALIDITY_UNDEFINED as isize,
        Never = sys::GPGME_VALIDITY_NEVER as isize,
        Marginal = sys::GPGME_VALIDITY_MARGINAL as isize,
        Full = sys::GPGME_VALIDITY_FULL as isize,
        Ultimate = sys::GPGME_VALIDITY_ULTIMATE as isize,
    }
}

impl fmt::Display for Validity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Validity::Unknown => write!(f, "?"),
            Validity::Undefined => write!(f, "q"),
            Validity::Never => write!(f, "n"),
            Validity::Marginal => write!(f, "m"),
            Validity::Full => write!(f, "f"),
            Validity::Ultimate => write!(f, "u"),
        }
    }
}

enum_from_primitive! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub enum KeyAlgorithm {
        Unknown         = -1,
        Rsa             = sys::GPGME_PK_RSA as isize,
        RsaEncrypt      = sys::GPGME_PK_RSA_E as isize,
        RsaSign         = sys::GPGME_PK_RSA_S as isize,
        ElGamalEncrypt  = sys::GPGME_PK_ELG_E as isize,
        Dsa             = sys::GPGME_PK_DSA as isize,
        Ecc             = sys::GPGME_PK_ECC as isize,
        ElGamal         = sys::GPGME_PK_ELG as isize,
        Ecdsa           = sys::GPGME_PK_ECDSA as isize,
        Ecdh            = sys::GPGME_PK_ECDH as isize,
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = unsafe {
            utils::from_cstr(sys::gpgme_pubkey_algo_name(*self as sys::gpgme_pubkey_algo_t))
        };
        write!(f, "{}", name.unwrap_or("Unknown"))
    }
}

enum_from_primitive! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub enum HashAlgorithm {
        Unknown       = -1,
        None          = sys::GPGME_MD_NONE as isize,
        Md2           = sys::GPGME_MD_MD2 as isize,
        Md4           = sys::GPGME_MD_MD4 as isize,
        Md5           = sys::GPGME_MD_MD5 as isize,
        Sha1          = sys::GPGME_MD_SHA1 as isize,
        Sha256        = sys::GPGME_MD_SHA256 as isize,
        Sha384        = sys::GPGME_MD_SHA384 as isize,
        Sha512        = sys::GPGME_MD_SHA512 as isize,
        Sha224        = sys::GPGME_MD_SHA224 as isize,
        Rmd160        = sys::GPGME_MD_RMD160 as isize,
        Tiger         = sys::GPGME_MD_TIGER as isize,
        Haval         = sys::GPGME_MD_HAVAL as isize,
        Crc32         = sys::GPGME_MD_CRC32 as isize,
        Crc32Rfc1510  = sys::GPGME_MD_CRC32_RFC1510 as isize,
        Crc24Rfc2440  = sys::GPGME_MD_CRC24_RFC2440 as isize,
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = unsafe {
            utils::from_cstr(sys::gpgme_hash_algo_name(*self as sys::gpgme_pubkey_algo_t))
        };
        write!(f, "{}", name.unwrap_or("Unknown"))
    }
}

#[derive(Debug)]
pub struct Key {
    raw: sys::gpgme_key_t,
}

impl Key {
    pub unsafe fn from_raw(raw: sys::gpgme_key_t) -> Key {
        Key { raw: raw }
    }

    pub fn as_raw(&self) -> sys::gpgme_key_t {
        self.raw
    }

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
            Protocol::from_u64((*self.raw).protocol as u64).unwrap_or(Protocol::Unknown)
        }
    }

    pub fn owner_trust(&self) -> Validity {
        unsafe {
            Validity::from_u64((*self.raw).owner_trust as u64).unwrap_or(Validity::Unknown)
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

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            sys::gpgme_key_unref(self.raw);
        }
    }
}

impl Clone for Key {
    fn clone(&self) -> Key {
        unsafe {
            sys::gpgme_key_ref(self.raw);
            Key { raw: self.raw }
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SubKey<'a> {
    raw: sys::gpgme_subkey_t,
    phantom: PhantomData<&'a Key>,
}

impl<'a> SubKey<'a> {
    pub unsafe fn from_raw<'b>(raw: sys::gpgme_subkey_t) -> SubKey<'b> {
        SubKey { raw: raw, phantom: PhantomData }
    }

    pub fn as_raw(&self) -> sys::gpgme_subkey_t {
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
            KeyAlgorithm::from_u64((*self.raw).pubkey_algo as u64).unwrap_or(KeyAlgorithm::Unknown)
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
    current: sys::gpgme_subkey_t,
    phantom: PhantomData<&'a Key>,
}

impl<'a> SubKeyIter<'a> {
    pub unsafe fn from_list<'b>(raw: sys::gpgme_subkey_t) -> SubKeyIter<'b> {
        SubKeyIter { current: raw, phantom: PhantomData }
    }
}

impl<'a> Iterator for SubKeyIter<'a> {
    list_iterator!(SubKey<'a>, SubKey::from_raw);
}

#[derive(Debug, Copy, Clone)]
pub struct UserId<'a> {
    raw: sys::gpgme_user_id_t,
    phantom: PhantomData<&'a Key>,
}

impl<'a> UserId<'a> {
    pub unsafe fn from_raw<'b>(raw: sys::gpgme_user_id_t) -> UserId<'b> {
        UserId { raw: raw, phantom: PhantomData }
    }

    pub fn as_raw(&self) -> sys::gpgme_user_id_t {
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
            Validity::from_u64((*self.raw).validity as u64).unwrap_or(Validity::Unknown)
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
    current: sys::gpgme_user_id_t,
    phantom: PhantomData<&'a Key>,
}

impl<'a> UserIdIter<'a> {
    pub unsafe fn from_list<'b>(raw: sys::gpgme_user_id_t) -> UserIdIter<'b> {
        UserIdIter { current: raw, phantom: PhantomData }
    }
}

impl<'a> Iterator for UserIdIter<'a> {
    list_iterator!(UserId<'a>, UserId::from_raw);
}

#[derive(Debug, Copy, Clone)]
pub struct KeySignature<'a> {
    raw: sys::gpgme_key_sig_t,
    phantom: PhantomData<&'a Key>,
}

impl<'a> KeySignature<'a> {
    pub unsafe fn from_raw<'b>(raw: sys::gpgme_key_sig_t) -> KeySignature<'b> {
        KeySignature { raw: raw, phantom: PhantomData }
    }

    pub fn as_raw(&self) -> sys::gpgme_key_sig_t {
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
            KeyAlgorithm::from_u64((*self.raw).pubkey_algo as u64).unwrap_or(KeyAlgorithm::Unknown)
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
    current: sys::gpgme_key_sig_t,
    phantom: PhantomData<&'a Key>,
}

impl<'a> KeySignatureIter<'a> {
    pub unsafe fn from_list<'b>(raw: sys::gpgme_key_sig_t) -> KeySignatureIter<'b> {
        KeySignatureIter { current: raw, phantom: PhantomData }
    }
}

impl<'a> Iterator for KeySignatureIter<'a> {
    list_iterator!(KeySignature<'a>, KeySignature::from_raw);
}
