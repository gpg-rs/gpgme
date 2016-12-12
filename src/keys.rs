use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::str::Utf8Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ffi;

use {Error, KeyAlgorithm, KeyListMode, Protocol, TofuInfo, Validity};
use notation::SignatureNotations;

pub struct Key(ffi::gpgme_key_t);

impl Drop for Key {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_key_unref(self.0);
        }
    }
}

impl Clone for Key {
    #[inline]
    fn clone(&self) -> Key {
        unsafe {
            ffi::gpgme_key_ref(self.0);
            Key(self.0)
        }
    }
}

impl Key {
    impl_wrapper!(Key: ffi::gpgme_key_t);

    pub fn is_revoked(&self) -> bool {
        unsafe { (*self.0).revoked() }
    }

    pub fn is_expired(&self) -> bool {
        unsafe { (*self.0).expired() }
    }

    pub fn is_disabled(&self) -> bool {
        unsafe { (*self.0).disabled() }
    }

    pub fn is_invalid(&self) -> bool {
        unsafe { (*self.0).invalid() }
    }

    pub fn can_encrypt(&self) -> bool {
        unsafe { (*self.0).can_encrypt() }
    }

    pub fn can_sign(&self) -> bool {
        unsafe { (*self.0).can_sign() }
    }

    pub fn can_certify(&self) -> bool {
        unsafe { (*self.0).can_certify() }
    }

    pub fn can_authenticate(&self) -> bool {
        unsafe { (*self.0).can_authenticate() }
    }

    pub fn is_qualified(&self) -> bool {
        unsafe { (*self.0).is_qualified() }
    }

    pub fn has_secret(&self) -> bool {
        unsafe { (*self.0).secret() }
    }

    #[deprecated(since = "0.5.0", note = "use `has_secret` instead")]
    pub fn is_secret(&self) -> bool {
        self.has_secret()
    }

    pub fn is_root(&self) -> bool {
        use std::ascii::AsciiExt;
        if let (Some(fpr), Some(chain_id)) = (self.fingerprint_raw(), self.chain_id_raw()) {
            fpr.to_bytes().eq_ignore_ascii_case(chain_id.to_bytes())
        } else {
            false
        }
    }

    pub fn owner_trust(&self) -> Validity {
        unsafe { Validity::from_raw((*self.0).owner_trust) }
    }

    pub fn protocol(&self) -> Protocol {
        unsafe { Protocol::from_raw((*self.0).protocol) }
    }

    pub fn issuer_serial(&self) -> Result<&str, Option<Utf8Error>> {
        self.issuer_serial_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn issuer_serial_raw(&self) -> Option<&CStr> {
        unsafe { (*self.0).issuer_serial.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn issuer_name(&self) -> Result<&str, Option<Utf8Error>> {
        self.issuer_name_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn issuer_name_raw(&self) -> Option<&CStr> {
        unsafe { (*self.0).issuer_name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn chain_id(&self) -> Result<&str, Option<Utf8Error>> {
        self.chain_id_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn chain_id_raw(&self) -> Option<&CStr> {
        unsafe { (*self.0).chain_id.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn id(&self) -> Result<&str, Option<Utf8Error>> {
        self.primary_key().map_or(Err(None), |k| k.id())
    }

    pub fn id_raw(&self) -> Option<&CStr> {
        self.primary_key().and_then(|k| k.id_raw())
    }

    pub fn short_id(&self) -> Result<&str, Option<Utf8Error>> {
        self.id().map(|s| if s.len() >= 8 { &s[(s.len() - 8)..] } else { s })
    }

    pub fn short_id_raw(&self) -> Option<&CStr> {
        self.id_raw().map(|s| {
            let bytes = s.to_bytes_with_nul();
            if bytes.len() >= 9 {
                // One extra for the null terminator
                unsafe { CStr::from_bytes_with_nul_unchecked(&bytes[(bytes.len() - 9)..]) }
            } else {
                s
            }
        })
    }

    pub fn fingerprint(&self) -> Result<&str, Option<Utf8Error>> {
        self.fingerprint_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn fingerprint_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.0)
                .fpr
                .as_ref()
                .map(|s| CStr::from_ptr(s))
                .or_else(|| self.primary_key().and_then(|k| k.fingerprint_raw()))
        }
    }

    pub fn key_list_mode(&self) -> KeyListMode {
        unsafe { KeyListMode::from_bits_truncate((*self.0).keylist_mode) }
    }

    pub fn primary_key(&self) -> Option<Subkey> {
        self.subkeys().next()
    }

    pub fn user_ids(&self) -> UserIds {
        unsafe { UserIds::from_list((*self.0).uids) }
    }

    pub fn subkeys(&self) -> Subkeys {
        unsafe { Subkeys::from_list((*self.0).subkeys) }
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Key")
            .field("protocol", &self.protocol().name().unwrap_or("<null>"))
            .field("owner_trust", &self.owner_trust().to_string())
            .field("issuer", &self.issuer_name().unwrap_or("<null>"))
            .field("fingerprint", &self.fingerprint().unwrap_or("<null>"))
            .field("list_mode", &self.key_list_mode())
            .field("can_sign", &self.can_sign())
            .field("can_encrypt", &self.can_encrypt())
            .field("can_certify", &self.can_certify())
            .field("can_auth", &self.can_authenticate())
            .field("raw", &self.0)
            .finish()
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Subkey<'a>(ffi::gpgme_subkey_t, PhantomData<&'a Key>);

impl<'a> Subkey<'a> {
    impl_wrapper!(@phantom Subkey: ffi::gpgme_subkey_t);

    pub fn id(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.id_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn id_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).keyid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn fingerprint(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.fingerprint_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn fingerprint_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).fpr.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn creation_time(&self) -> Option<SystemTime> {
        let timestamp = unsafe { (*self.0).timestamp };
        if timestamp > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(timestamp as u64))
        } else {
            None
        }
    }

    pub fn expiration_time(&self) -> Option<SystemTime> {
        let expires = unsafe { (*self.0).expires };
        if expires > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(expires as u64))
        } else {
            None
        }
    }

    pub fn never_expires(&self) -> bool {
        self.expiration_time().is_none()
    }

    pub fn is_revoked(&self) -> bool {
        unsafe { (*self.0).revoked() }
    }

    pub fn is_expired(&self) -> bool {
        unsafe { (*self.0).expired() }
    }

    pub fn is_invalid(&self) -> bool {
        unsafe { (*self.0).invalid() }
    }

    pub fn is_disabled(&self) -> bool {
        unsafe { (*self.0).disabled() }
    }

    pub fn can_encrypt(&self) -> bool {
        unsafe { (*self.0).can_encrypt() }
    }

    pub fn can_sign(&self) -> bool {
        unsafe { (*self.0).can_sign() }
    }

    pub fn can_certify(&self) -> bool {
        unsafe { (*self.0).can_certify() }
    }

    pub fn can_authenticate(&self) -> bool {
        unsafe { (*self.0).can_authenticate() }
    }

    pub fn is_qualified(&self) -> bool {
        unsafe { (*self.0).is_qualified() }
    }

    pub fn is_card_key(&self) -> bool {
        unsafe { (*self.0).is_cardkey() }
    }

    pub fn is_secret(&self) -> bool {
        unsafe { (*self.0).secret() }
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        unsafe { KeyAlgorithm::from_raw((*self.0).pubkey_algo) }
    }

    pub fn algorithm_name(&self) -> ::Result<String> {
        unsafe {
            match ffi::gpgme_pubkey_algo_string(self.0).as_mut() {
                Some(raw) => {
                    let result = CStr::from_ptr(raw)
                        .to_str()
                        .expect("algorithm name is not valid utf-8")
                        .to_owned();
                    ffi::gpgme_free(raw as *mut _ as *mut _);
                    Ok(result)
                }
                None => Err(Error::last_os_error()),
            }
        }
    }

    pub fn keygrip(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.keygrip_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn keygrip_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).keygrip.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn length(&self) -> usize {
        unsafe { (*self.0).length as usize }
    }

    pub fn card_serial_number(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.card_serial_number_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn card_serial_number_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).card_number.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn curve(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.curve_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn curve_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).curve.as_ref().map(|s| CStr::from_ptr(s)) }
    }
}

#[derive(Debug, Clone)]
pub struct Subkeys<'a> {
    current: ffi::gpgme_subkey_t,
    left: Option<usize>,
    phantom: PhantomData<&'a Key>,
}

impl<'a> Subkeys<'a> {
    pub unsafe fn from_list(first: ffi::gpgme_subkey_t) -> Self {
        Subkeys {
            current: first,
            left: count_list!(first),
            phantom: PhantomData,
        }
    }
}

impl<'a> Iterator for Subkeys<'a> {
    list_iterator!(Subkey<'a>, Subkey::from_raw);
}

#[derive(Copy, Clone)]
pub struct UserId<'a>(ffi::gpgme_user_id_t, PhantomData<&'a Key>);

impl<'a> UserId<'a> {
    impl_wrapper!(@phantom UserId: ffi::gpgme_user_id_t);

    pub fn id(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.id_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn id_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).uid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn name(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.name_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn name_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn email(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.email_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn email_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).email.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn comment(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.comment_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn comment_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).comment.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn address(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.address_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn address_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).address.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn validity(&self) -> Validity {
        unsafe { Validity::from_raw((*self.0).validity) }
    }

    pub fn is_revoked(&self) -> bool {
        unsafe { (*self.0).revoked() }
    }

    pub fn is_invalid(&self) -> bool {
        unsafe { (*self.0).invalid() }
    }

    pub fn signatures(&self) -> Signatures {
        unsafe { Signatures::from_list((*self.0).signatures) }
    }

    pub fn tofu_info(&self) -> Option<TofuInfo> {
        unsafe { (*self.0).tofu.as_mut().map(|t| TofuInfo::from_raw(t)) }
    }
}

impl<'a> fmt::Debug for UserId<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("UserId")
            .field("name", &self.name().unwrap_or("<null>"))
            .field("email", &self.email().unwrap_or("<null>"))
            .field("comment", &self.comment().unwrap_or("<null>"))
            .field("validity", &self.validity().to_string())
            .field("revoked", &self.is_revoked())
            .field("invalid", &self.is_invalid())
            .field("raw", &self.0)
            .finish()
    }
}

impl<'a> fmt::Display for UserId<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let uid = self.id_raw().map(|s| s.to_string_lossy()).unwrap_or("".into());
        write!(f, "{}", uid)
    }
}

#[derive(Debug, Clone)]
pub struct UserIds<'a> {
    current: ffi::gpgme_user_id_t,
    left: Option<usize>,
    phantom: PhantomData<&'a Key>,
}

impl<'a> UserIds<'a> {
    pub unsafe fn from_list(first: ffi::gpgme_user_id_t) -> Self {
        UserIds {
            current: first,
            left: count_list!(first),
            phantom: PhantomData,
        }
    }
}

impl<'a> Iterator for UserIds<'a> {
    list_iterator!(UserId<'a>, UserId::from_raw);
}

#[derive(Debug, Copy, Clone)]
pub struct Signature<'a>(ffi::gpgme_key_sig_t, PhantomData<&'a Key>);

impl<'a> Signature<'a> {
    impl_wrapper!(@phantom Signature: ffi::gpgme_key_sig_t);

    pub fn signer_key_id(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.signer_key_id_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn signer_key_id_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).keyid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        unsafe { KeyAlgorithm::from_raw((*self.0).pubkey_algo) }
    }

    pub fn creation_time(&self) -> Option<SystemTime> {
        let timestamp = unsafe { (*self.0).timestamp };
        if timestamp > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(timestamp as u64))
        } else {
            None
        }
    }

    pub fn expiration_time(&self) -> Option<SystemTime> {
        let expires = unsafe { (*self.0).expires };
        if expires > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(expires as u64))
        } else {
            None
        }
    }

    pub fn never_expires(&self) -> bool {
        self.expiration_time().is_none()
    }

    pub fn is_revokation(&self) -> bool {
        unsafe { (*self.0).revoked() }
    }

    pub fn is_invalid(&self) -> bool {
        unsafe { (*self.0).invalid() }
    }

    pub fn is_expired(&self) -> bool {
        unsafe { (*self.0).expired() }
    }

    pub fn is_exportable(&self) -> bool {
        unsafe { (*self.0).exportable() }
    }

    pub fn signer_user_id(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.signer_user_id_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn signer_user_id_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).uid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn signer_name(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.signer_name_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn signer_name_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn signer_email(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.signer_email_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn signer_email_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).email.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn signer_comment(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.signer_comment_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn signer_comment_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.0).comment.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn cert_class(&self) -> u64 {
        unsafe { (*self.0).sig_class.into() }
    }

    pub fn status(&self) -> Error {
        unsafe { Error::new((*self.0).status) }
    }

    pub fn policy_url(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.policy_url_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn policy_url_raw(&self) -> Option<&'a CStr> {
        unsafe {
            let mut notation = (*self.0).notations;
            while !notation.is_null() {
                if (*notation).name.is_null() {
                    return (*notation).value.as_ref().map(|s| CStr::from_ptr(s));
                }
                notation = (*notation).next;
            }
            None
        }
    }

    pub fn notations(&self) -> SignatureNotations<'a, Key> {
        unsafe { SignatureNotations::from_list((*self.0).notations) }
    }
}

#[derive(Debug, Clone)]
pub struct Signatures<'a> {
    current: ffi::gpgme_key_sig_t,
    left: Option<usize>,
    phantom: PhantomData<&'a Key>,
}

impl<'a> Signatures<'a> {
    pub unsafe fn from_list(first: ffi::gpgme_key_sig_t) -> Self {
        Signatures {
            current: first,
            left: count_list!(first),
            phantom: PhantomData,
        }
    }
}

impl<'a> Iterator for Signatures<'a> {
    list_iterator!(Signature<'a>, Signature::from_raw);
}
