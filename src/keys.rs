use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::str::Utf8Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ffi;

use {Error, KeyAlgorithm, KeyListMode, NonZero, Protocol, Validity};
use notation::SignatureNotations;

pub struct Key(NonZero<ffi::gpgme_key_t>);

unsafe impl Send for Key {}
unsafe impl Sync for Key {}

impl Drop for Key {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_key_unref(self.as_raw());
        }
    }
}

impl Clone for Key {
    #[inline]
    fn clone(&self) -> Key {
        unsafe {
            ffi::gpgme_key_ref(self.as_raw());
            Key(self.0)
        }
    }
}

impl Key {
    impl_wrapper!(Key: ffi::gpgme_key_t);

    #[inline]
    pub fn is_revoked(&self) -> bool {
        unsafe { (*self.as_raw()).revoked() }
    }

    #[inline]
    pub fn is_expired(&self) -> bool {
        unsafe { (*self.as_raw()).expired() }
    }

    #[inline]
    pub fn is_disabled(&self) -> bool {
        unsafe { (*self.as_raw()).disabled() }
    }

    #[inline]
    pub fn is_invalid(&self) -> bool {
        unsafe { (*self.as_raw()).invalid() }
    }

    #[inline]
    pub fn can_encrypt(&self) -> bool {
        unsafe { (*self.as_raw()).can_encrypt() }
    }

    #[inline]
    pub fn can_sign(&self) -> bool {
        unsafe { (*self.as_raw()).can_sign() }
    }

    #[inline]
    pub fn can_certify(&self) -> bool {
        unsafe { (*self.as_raw()).can_certify() }
    }

    #[inline]
    pub fn can_authenticate(&self) -> bool {
        unsafe { (*self.as_raw()).can_authenticate() }
    }

    #[inline]
    pub fn is_qualified(&self) -> bool {
        unsafe { (*self.as_raw()).is_qualified() }
    }

    #[inline]
    pub fn has_secret(&self) -> bool {
        unsafe { (*self.as_raw()).secret() }
    }

    #[inline]
    pub fn is_root(&self) -> bool {
        use std::ascii::AsciiExt;
        if let (Some(fpr), Some(chain_id)) = (self.fingerprint_raw(), self.chain_id_raw()) {
            fpr.to_bytes().eq_ignore_ascii_case(chain_id.to_bytes())
        } else {
            false
        }
    }

    #[inline]
    pub fn owner_trust(&self) -> Validity {
        unsafe { Validity::from_raw((*self.as_raw()).owner_trust) }
    }

    #[inline]
    pub fn protocol(&self) -> Protocol {
        unsafe { Protocol::from_raw((*self.as_raw()).protocol) }
    }

    #[inline]
    pub fn issuer_serial(&self) -> Result<&str, Option<Utf8Error>> {
        self.issuer_serial_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn issuer_serial_raw(&self) -> Option<&CStr> {
        unsafe { (*self.as_raw()).issuer_serial.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn issuer_name(&self) -> Result<&str, Option<Utf8Error>> {
        self.issuer_name_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn issuer_name_raw(&self) -> Option<&CStr> {
        unsafe { (*self.as_raw()).issuer_name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn chain_id(&self) -> Result<&str, Option<Utf8Error>> {
        self.chain_id_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn chain_id_raw(&self) -> Option<&CStr> {
        unsafe { (*self.as_raw()).chain_id.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn id(&self) -> Result<&str, Option<Utf8Error>> {
        self.primary_key().map_or(Err(None), |k| k.id())
    }

    #[inline]
    pub fn id_raw(&self) -> Option<&CStr> {
        self.primary_key().and_then(|k| k.id_raw())
    }

    #[inline]
    pub fn short_id(&self) -> Result<&str, Option<Utf8Error>> {
        self.id().map(|s| if s.len() >= 8 { &s[(s.len() - 8)..] } else { s })
    }

    #[inline]
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

    #[inline]
    pub fn fingerprint(&self) -> Result<&str, Option<Utf8Error>> {
        self.fingerprint_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[cfg(not(feature = "v1_7_0"))]
    #[inline]
    pub fn fingerprint_raw(&self) -> Option<&CStr> {
        self.primary_key().and_then(|k| k.fingerprint_raw())
    }

    #[cfg(feature = "v1_7_0")]
    #[inline]
    pub fn fingerprint_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.as_raw())
                .fpr
                .as_ref()
                .map(|s| CStr::from_ptr(s))
                .or_else(|| self.primary_key().and_then(|k| k.fingerprint_raw()))
        }
    }

    #[inline]
    pub fn key_list_mode(&self) -> KeyListMode {
        unsafe { KeyListMode::from_bits_truncate((*self.as_raw()).keylist_mode) }
    }

    #[inline]
    pub fn primary_key(&self) -> Option<Subkey> {
        self.subkeys().next()
    }

    #[inline]
    pub fn user_ids(&self) -> UserIds {
        unsafe { UserIds::from_list((*self.as_raw()).uids) }
    }

    #[inline]
    pub fn subkeys(&self) -> Subkeys {
        unsafe { Subkeys::from_list((*self.as_raw()).subkeys) }
    }

    #[inline]
    pub fn updated(&self) -> ::Result<Key> {
        let mut ctx = try!(::Context::from_protocol(self.protocol()));
        let _ = ctx.set_key_list_mode(::KEY_LIST_MODE_LOCAL | ::KEY_LIST_MODE_SIGS |
                                      ::KEY_LIST_MODE_SIG_NOTATIONS |
                                      ::KEY_LIST_MODE_VALIDATE |
                                      ::KEY_LIST_MODE_WITH_TOFU);
        if self.has_secret() {
            ctx.get_key(self)
        } else {
            ctx.get_secret_key(self)
        }
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
            .field("raw", &*self.0)
            .finish()
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Subkey<'a>(NonZero<ffi::gpgme_subkey_t>, PhantomData<&'a Key>);

unsafe impl<'a> Send for Subkey<'a> {}
unsafe impl<'a> Sync for Subkey<'a> {}

impl<'a> Subkey<'a> {
    impl_wrapper!(@phantom Subkey: ffi::gpgme_subkey_t);

    #[inline]
    pub fn id(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.id_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn id_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).keyid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn fingerprint(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.fingerprint_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn fingerprint_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).fpr.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn creation_time(&self) -> Option<SystemTime> {
        let timestamp = unsafe { (*self.as_raw()).timestamp };
        if timestamp > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(timestamp as u64))
        } else {
            None
        }
    }

    #[inline]
    pub fn expiration_time(&self) -> Option<SystemTime> {
        let expires = unsafe { (*self.as_raw()).expires };
        if expires > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(expires as u64))
        } else {
            None
        }
    }

    #[inline]
    pub fn never_expires(&self) -> bool {
        self.expiration_time().is_none()
    }

    #[inline]
    pub fn is_revoked(&self) -> bool {
        unsafe { (*self.as_raw()).revoked() }
    }

    #[inline]
    pub fn is_expired(&self) -> bool {
        unsafe { (*self.as_raw()).expired() }
    }

    #[inline]
    pub fn is_invalid(&self) -> bool {
        unsafe { (*self.as_raw()).invalid() }
    }

    #[inline]
    pub fn is_disabled(&self) -> bool {
        unsafe { (*self.as_raw()).disabled() }
    }

    #[inline]
    pub fn can_encrypt(&self) -> bool {
        unsafe { (*self.as_raw()).can_encrypt() }
    }

    #[inline]
    pub fn can_sign(&self) -> bool {
        unsafe { (*self.as_raw()).can_sign() }
    }

    #[inline]
    pub fn can_certify(&self) -> bool {
        unsafe { (*self.as_raw()).can_certify() }
    }

    #[inline]
    pub fn can_authenticate(&self) -> bool {
        unsafe { (*self.as_raw()).can_authenticate() }
    }

    #[inline]
    pub fn is_qualified(&self) -> bool {
        unsafe { (*self.as_raw()).is_qualified() }
    }

    #[inline]
    pub fn is_card_key(&self) -> bool {
        unsafe { (*self.as_raw()).is_cardkey() }
    }

    #[inline]
    pub fn is_secret(&self) -> bool {
        unsafe { (*self.as_raw()).secret() }
    }

    #[inline]
    pub fn algorithm(&self) -> KeyAlgorithm {
        unsafe { KeyAlgorithm::from_raw((*self.as_raw()).pubkey_algo) }
    }

    #[cfg(feature = "v1_7_0")]
    #[inline]
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

    #[inline]
    #[cfg(feature = "v1_7_0")]
    pub fn keygrip(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.keygrip_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    #[cfg(feature = "v1_7_0")]
    pub fn keygrip_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).keygrip.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn length(&self) -> usize {
        unsafe { (*self.as_raw()).length as usize }
    }

    #[inline]
    pub fn card_serial_number(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.card_serial_number_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn card_serial_number_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).card_number.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    #[cfg(feature = "v1_5_0")]
    pub fn curve(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.curve_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    #[cfg(feature = "v1_5_0")]
    pub fn curve_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).curve.as_ref().map(|s| CStr::from_ptr(s)) }
    }
}

#[derive(Debug, Clone)]
pub struct Subkeys<'a> {
    current: Option<Subkey<'a>>,
    left: Option<usize>,
}

impl<'a> Subkeys<'a> {
    pub unsafe fn from_list(first: ffi::gpgme_subkey_t) -> Self {
        Subkeys {
            current: first.as_mut().map(|r| Subkey::from_raw(r)),
            left: count_list!(first),
        }
    }
}

impl<'a> Iterator for Subkeys<'a> {
    list_iterator!(Subkey<'a>, Subkey::from_raw);
}

#[derive(Copy, Clone)]
pub struct UserId<'a>(NonZero<ffi::gpgme_user_id_t>, PhantomData<&'a Key>);

unsafe impl<'a> Send for UserId<'a> {}
unsafe impl<'a> Sync for UserId<'a> {}

impl<'a> UserId<'a> {
    impl_wrapper!(@phantom UserId: ffi::gpgme_user_id_t);

    #[inline]
    pub fn id(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.id_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn id_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).uid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn name(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.name_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn name_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn email(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.email_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn email_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).email.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn comment(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.comment_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn comment_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).comment.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn address(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.address_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn address_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).address.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn validity(&self) -> Validity {
        unsafe { Validity::from_raw((*self.as_raw()).validity) }
    }

    #[inline]
    pub fn is_revoked(&self) -> bool {
        unsafe { (*self.as_raw()).revoked() }
    }

    #[inline]
    pub fn is_invalid(&self) -> bool {
        unsafe { (*self.as_raw()).invalid() }
    }

    #[inline]
    pub fn signatures(&self) -> UserIdSignatures {
        unsafe { UserIdSignatures::from_list((*self.as_raw()).signatures) }
    }

    #[inline]
    #[cfg(feature = "v1_7_0")]
    pub fn tofu_info(&self) -> Option<::TofuInfo> {
        unsafe { (*self.as_raw()).tofu.as_mut().map(|t| ::TofuInfo::from_raw(t)) }
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
            .field("raw", &*self.0)
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
    current: Option<UserId<'a>>,
    left: Option<usize>,
}

impl<'a> UserIds<'a> {
    pub unsafe fn from_list(first: ffi::gpgme_user_id_t) -> Self {
        UserIds {
            current: first.as_mut().map(|r| UserId::from_raw(r)),
            left: count_list!(first),
        }
    }
}

impl<'a> Iterator for UserIds<'a> {
    list_iterator!(UserId<'a>, UserId::from_raw);
}

#[derive(Debug, Copy, Clone)]
pub struct UserIdSignature<'a>(NonZero<ffi::gpgme_key_sig_t>, PhantomData<&'a Key>);

unsafe impl<'a> Send for UserIdSignature<'a> {}
unsafe impl<'a> Sync for UserIdSignature<'a> {}

impl<'a> UserIdSignature<'a> {
    impl_wrapper!(@phantom UserIdSignature: ffi::gpgme_key_sig_t);

    #[inline]
    pub fn signer_key_id(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.signer_key_id_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn signer_key_id_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).keyid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn algorithm(&self) -> KeyAlgorithm {
        unsafe { KeyAlgorithm::from_raw((*self.as_raw()).pubkey_algo) }
    }

    #[inline]
    pub fn creation_time(&self) -> Option<SystemTime> {
        let timestamp = unsafe { (*self.as_raw()).timestamp };
        if timestamp > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(timestamp as u64))
        } else {
            None
        }
    }

    #[inline]
    pub fn expiration_time(&self) -> Option<SystemTime> {
        let expires = unsafe { (*self.as_raw()).expires };
        if expires > 0 {
            Some(UNIX_EPOCH + Duration::from_secs(expires as u64))
        } else {
            None
        }
    }

    #[inline]
    pub fn never_expires(&self) -> bool {
        self.expiration_time().is_none()
    }

    #[inline]
    pub fn is_revokation(&self) -> bool {
        unsafe { (*self.as_raw()).revoked() }
    }

    #[inline]
    pub fn is_invalid(&self) -> bool {
        unsafe { (*self.as_raw()).invalid() }
    }

    #[inline]
    pub fn is_expired(&self) -> bool {
        unsafe { (*self.as_raw()).expired() }
    }

    #[inline]
    pub fn is_exportable(&self) -> bool {
        unsafe { (*self.as_raw()).exportable() }
    }

    #[inline]
    pub fn signer_user_id(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.signer_user_id_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn signer_user_id_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).uid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn signer_name(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.signer_name_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn signer_name_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn signer_email(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.signer_email_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn signer_email_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).email.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn signer_comment(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.signer_comment_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn signer_comment_raw(&self) -> Option<&'a CStr> {
        unsafe { (*self.as_raw()).comment.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn cert_class(&self) -> u64 {
        unsafe { (*self.as_raw()).sig_class.into() }
    }

    #[inline]
    pub fn status(&self) -> Error {
        unsafe { Error::new((*self.as_raw()).status) }
    }

    #[inline]
    pub fn policy_url(&self) -> Result<&'a str, Option<Utf8Error>> {
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
    pub fn notations(&self) -> SignatureNotations<'a, Key> {
        unsafe { SignatureNotations::from_list((*self.as_raw()).notations) }
    }
}

#[derive(Debug, Clone)]
pub struct UserIdSignatures<'a> {
    current: Option<UserIdSignature<'a>>,
    left: Option<usize>,
}

impl<'a> UserIdSignatures<'a> {
    pub unsafe fn from_list(first: ffi::gpgme_key_sig_t) -> Self {
        UserIdSignatures {
            current: first.as_mut().map(|r| UserIdSignature::from_raw(r)),
            left: count_list!(first),
        }
    }
}

impl<'a> Iterator for UserIdSignatures<'a> {
    list_iterator!(UserIdSignature<'a>, UserIdSignature::from_raw);
}
