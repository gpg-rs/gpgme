use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::str;

use enum_primitive::FromPrimitive;

use gpgme_sys as sys;

use error::Error;
use context::Protocol;
use ops::KeyListMode;

enum_from_primitive! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub enum Validity {
        Unknown,
        Undefined,
        Never,
        Marginal,
        Full,
        Ultimate,
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
        Rsa             = 1,
        RsaEncrypt      = 2,
        RsaSign         = 3,
        ElGamalEncrypt  = 16,
        Dsa             = 17,
        ElGamal         = 20,
        Ecdsa           = 301,
        Ecdh            = 302,
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = unsafe {
            let algo = sys::gpgme_pubkey_algo_t::from_u32(*self as u32);
            algo.map(|a| CStr::from_ptr(sys::gpgme_pubkey_algo_name(a) as *const _).to_bytes())
        };
        write!(f, "{}", name.and_then(|b| str::from_utf8(b).ok()).unwrap_or("Unknown"))
    }
}

enum_from_primitive! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub enum HashAlgorithm {
        Unknown       = -1,
        None          = 0,
        Md5           = 1,
        Sha1          = 2,
        Rmd160        = 3,
        Md2           = 5,
        Tiger         = 6,
        Haval         = 7,
        Sha256        = 8,
        Sha384        = 9,
        Sha512        = 10,
        Md4           = 301,
        Crc32         = 302,
        Crc32Rfc1510  = 303,
        Crc24Rfc2440  = 304,
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = unsafe {
            let algo = sys::gpgme_hash_algo_t::from_u32(*self as u32);
            algo.map(|a| CStr::from_ptr(sys::gpgme_hash_algo_name(a) as *const _).to_bytes())
        };
        write!(f, "{}", name.and_then(|b| str::from_utf8(b).ok()).unwrap_or("Unknown"))
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
            Protocol::from_u32((*self.raw).protocol as u32).unwrap_or(Protocol::Unknown)
        }
    }

    pub fn owner_trust(&self) -> Validity {
        unsafe {
            Validity::from_u32((*self.raw).owner_trust as u32).unwrap_or(Validity::Unknown)
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
    fn clone(&self) -> Self {
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
            let id = (*self.raw).keyid;
            if !id.is_null() {
                str::from_utf8(CStr::from_ptr(id).to_bytes()).ok()
            } else {
                None
            }
        }
    }

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

    pub fn algorithm(&self) -> KeyAlgorithm {
        unsafe {
            KeyAlgorithm::from_u32((*self.raw).pubkey_algo as u32).unwrap_or(KeyAlgorithm::Unknown)
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
    type Item = SubKey<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current;
        if !current.is_null() {
            unsafe {
                self.current = (*current).next;
                Some(SubKey::from_raw(current))
            }
        } else {
            None
        }
    }
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
            let uid = (*self.raw).uid;
            if !uid.is_null() {
                str::from_utf8(CStr::from_ptr(uid).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    pub fn name(&self) -> Option<&'a str> {
        unsafe {
            let name = (*self.raw).name;
            if !name.is_null() {
                str::from_utf8(CStr::from_ptr(name).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    pub fn email(&self) -> Option<&'a str> {
        unsafe {
            let email = (*self.raw).email;
            if !email.is_null() {
                str::from_utf8(CStr::from_ptr(email).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    pub fn comment(&self) -> Option<&'a str> {
        unsafe {
            let comment = (*self.raw).comment;
            if !comment.is_null() {
                str::from_utf8(CStr::from_ptr(comment).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    pub fn validity(&self) -> Validity {
        unsafe {
            Validity::from_u32((*self.raw).validity as u32).unwrap_or(Validity::Unknown)
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
    type Item = UserId<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current;
        if !current.is_null() {
            unsafe {
                self.current = (*current).next;
                Some(UserId::from_raw(current))
            }
        } else {
            None
        }
    }
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

    pub fn revoked(&self) -> bool {
        unsafe { (*self.raw).revoked() }
    }

    pub fn expired(&self) -> bool {
        unsafe { (*self.raw).expired() }
    }

    pub fn invalid(&self) -> bool {
        unsafe { (*self.raw).invalid() }
    }

    pub fn exportable(&self) -> bool {
        unsafe { (*self.raw).exportable() }
    }

    pub fn key_id(&self) -> Option<&'a str> {
        unsafe {
            let id = (*self.raw).keyid;
            if !id.is_null() {
                str::from_utf8(CStr::from_ptr(id).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    pub fn uid(&self) -> Option<&'a str> {
        unsafe {
            let uid = (*self.raw).uid;
            if !uid.is_null() {
                str::from_utf8(CStr::from_ptr(uid).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    pub fn name(&self) -> Option<&'a str> {
        unsafe {
            let name = (*self.raw).name;
            if !name.is_null() {
                str::from_utf8(CStr::from_ptr(name).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    pub fn email(&self) -> Option<&'a str> {
        unsafe {
            let email = (*self.raw).email;
            if !email.is_null() {
                str::from_utf8(CStr::from_ptr(email).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    pub fn comment(&self) -> Option<&'a str> {
        unsafe {
            let comment = (*self.raw).comment;
            if !comment.is_null() {
                str::from_utf8(CStr::from_ptr(comment).to_bytes()).ok()
            } else {
                None
            }
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
            KeyAlgorithm::from_u32((*self.raw).pubkey_algo as u32).unwrap_or(KeyAlgorithm::Unknown)
        }
    }

    pub fn status(&self) -> Error {
        unsafe { Error::new((*self.raw).status) }
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
    type Item = KeySignature<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current;
        if !current.is_null() {
            unsafe {
                self.current = (*current).next;
                Some(KeySignature::from_raw(current))
            }
        } else {
            None
        }
    }
}
