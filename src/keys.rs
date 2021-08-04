use std::{
    ffi::CStr,
    fmt,
    marker::PhantomData,
    str::Utf8Error,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ffi::{self, require_gpgme_ver};

use crate::{
    notation::SignatureNotations, Error, KeyAlgorithm, KeyListMode, NonNull, Protocol, Validity,
};

/// Upstream documentation:
/// [`gpgme_key_t`](https://www.gnupg.org/documentation/manuals/gpgme/Key-objects.html#index-gpgme_005fkey_005ft)
pub struct Key(NonNull<ffi::gpgme_key_t>);

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
    impl_wrapper!(ffi::gpgme_key_t);

    #[inline]
    pub fn is_bad(&self) -> bool {
        self.is_revoked() || self.is_expired() || self.is_disabled() || self.is_invalid()
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
    pub fn is_de_vs(&self) -> bool {
        self.subkeys().all(|x| x.is_de_vs())
    }

    #[inline]
    pub fn has_secret(&self) -> bool {
        unsafe { (*self.as_raw()).secret() }
    }

    #[inline]
    pub fn is_root(&self) -> bool {
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
        self.issuer_serial_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn issuer_serial_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.as_raw())
                .issuer_serial
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn issuer_name(&self) -> Result<&str, Option<Utf8Error>> {
        self.issuer_name_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn issuer_name_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.as_raw())
                .issuer_name
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn chain_id(&self) -> Result<&str, Option<Utf8Error>> {
        self.chain_id_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn chain_id_raw(&self) -> Option<&CStr> {
        unsafe {
            (*self.as_raw())
                .chain_id
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn id(&self) -> Result<&str, Option<Utf8Error>> {
        self.primary_key().map_or(Err(None), |k| k.id())
    }

    #[inline]
    pub fn id_raw(&self) -> Option<&CStr> {
        self.primary_key()?.id_raw()
    }

    #[inline]
    pub fn short_id(&self) -> Result<&str, Option<Utf8Error>> {
        self.short_id_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
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
        self.fingerprint_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn fingerprint_raw(&self) -> Option<&CStr> {
        require_gpgme_ver! {
            (1, 7) => {
                unsafe {
                    (*self.as_raw())
                        .fpr
                        .as_ref()
                        .map(|s| CStr::from_ptr(s))
                        .or_else(|| self.primary_key()?.fingerprint_raw())
                }
            } else {
                self.primary_key()?.fingerprint_raw()
            }
        }
    }

    #[inline]
    pub fn key_list_mode(&self) -> KeyListMode {
        unsafe { KeyListMode::from_bits_truncate((*self.as_raw()).keylist_mode) }
    }

    #[inline]
    pub fn origin(&self) -> crate::KeyOrigin {
        unsafe { crate::KeyOrigin::from_raw((*self.as_raw()).origin()) }
    }

    #[inline]
    pub fn primary_key(&self) -> Option<Subkey<'_>> {
        self.subkeys().next()
    }

    #[inline]
    pub fn user_ids(&self) -> UserIds<'_> {
        unsafe { UserIds::from_list((*self.as_raw()).uids) }
    }

    #[inline]
    pub fn subkeys(&self) -> Subkeys<'_> {
        unsafe { Subkeys::from_list((*self.as_raw()).subkeys) }
    }

    #[inline]
    pub fn last_update(&self) -> SystemTime {
        let timestamp = unsafe { (*self.as_raw()).last_update };
        UNIX_EPOCH + Duration::from_secs(timestamp.into())
    }

    #[inline]
    pub fn update(&mut self) -> crate::Result<()> {
        *self = self.updated()?;
        Ok(())
    }

    #[inline]
    pub fn updated(&self) -> crate::Result<Key> {
        let mut ctx = crate::Context::from_protocol(self.protocol())?;
        let _ = ctx.set_key_list_mode(self.key_list_mode());
        ctx.refresh_key(self)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("raw", &self.as_raw())
            .field("fingerprint", &self.fingerprint_raw())
            .field("protocol", &self.protocol())
            .field("owner_trust", &self.owner_trust())
            .field("issuer", &self.issuer_name_raw())
            .field("origin", &self.origin())
            .field("last_update", &self.last_update())
            .field("list_mode", &self.key_list_mode())
            .field("has_secret", &self.has_secret())
            .field("expired", &self.is_expired())
            .field("revoked", &self.is_revoked())
            .field("invalid", &self.is_invalid())
            .field("disabled", &self.is_disabled())
            .field("can_sign", &self.can_sign())
            .field("can_encrypt", &self.can_encrypt())
            .field("can_certify", &self.can_certify())
            .field("can_auth", &self.can_authenticate())
            .field("user_ids", &self.user_ids())
            .field("subkeys", &self.subkeys())
            .finish()
    }
}

/// Upstream documentation: [`gpgme_subkey_t`](https://www.gnupg.org/documentation/manuals/gpgme/Key-objects.html#index-gpgme_005fsubkey_005ft)
#[derive(Copy, Clone)]
pub struct Subkey<'key>(NonNull<ffi::gpgme_subkey_t>, PhantomData<&'key Key>);

unsafe impl Send for Subkey<'_> {}
unsafe impl Sync for Subkey<'_> {}

impl<'key> Subkey<'key> {
    impl_wrapper!(ffi::gpgme_subkey_t, PhantomData);

    #[inline]
    pub fn id(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.id_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn id_raw(&self) -> Option<&'key CStr> {
        unsafe { (*self.as_raw()).keyid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn fingerprint(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.fingerprint_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn fingerprint_raw(&self) -> Option<&'key CStr> {
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
    pub fn is_bad(&self) -> bool {
        self.is_revoked() || self.is_expired() || self.is_disabled() || self.is_invalid()
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
    pub fn is_de_vs(&self) -> bool {
        unsafe { (*self.as_raw()).is_de_vs() }
    }

    #[inline]
    pub fn algorithm(&self) -> KeyAlgorithm {
        unsafe { KeyAlgorithm::from_raw((*self.as_raw()).pubkey_algo) }
    }

    /// Upstream documentation: [`gpgme_pubkey_algo_string`](https://www.gnupg.org/documentation/manuals/gpgme/Public-Key-Algorithms.html#index-gpgme_005fpubkey_005falgo_005fstring)
    #[inline]
    pub fn algorithm_name(&self) -> crate::Result<String> {
        unsafe {
            match ffi::gpgme_pubkey_algo_string(self.as_raw()).as_mut() {
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
    pub fn keygrip(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.keygrip_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn keygrip_raw(&self) -> Option<&'key CStr> {
        require_gpgme_ver! {
            (1, 7) => {
                unsafe { (*self.as_raw()).keygrip.as_ref().map(|s| CStr::from_ptr(s)) }
            } else {
                None
            }
        }
    }

    #[inline]
    pub fn length(&self) -> usize {
        unsafe { (*self.as_raw()).length as usize }
    }

    #[inline]
    pub fn card_serial_number(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.card_serial_number_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn card_serial_number_raw(&self) -> Option<&'key CStr> {
        unsafe {
            (*self.as_raw())
                .card_number
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn curve(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.curve_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn curve_raw(&self) -> Option<&'key CStr> {
        require_gpgme_ver! {
            (1,5) => {
                unsafe { (*self.as_raw()).curve.as_ref().map(|s| CStr::from_ptr(s)) }
            } else {
                None
            }
        }
    }
}

impl fmt::Debug for Subkey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subkey")
            .field("raw", &self.as_raw())
            .field("fingerprint", &self.fingerprint_raw())
            .field("secret", &self.is_secret())
            .field("algorithm", &self.algorithm())
            .field("expired", &self.is_expired())
            .field("creation_time", &self.creation_time())
            .field("expiration_time", &self.expiration_time())
            .field("curve", &self.curve_raw())
            .field("length", &self.length())
            .field("card_key", &self.is_card_key())
            .field("card_serial_number", &self.card_serial_number_raw())
            .field("revoked", &self.is_revoked())
            .field("invalid", &self.is_invalid())
            .field("disabled", &self.is_disabled())
            .field("can_sign", &self.can_sign())
            .field("can_encrypt", &self.can_encrypt())
            .field("can_certify", &self.can_certify())
            .field("can_auth", &self.can_authenticate())
            .finish()
    }
}

impl_list_iterator!(pub struct Subkeys(Subkey: ffi::gpgme_subkey_t));

/// Upstream documentation: [`gpgme_user_id_t`](https://www.gnupg.org/documentation/manuals/gpgme/Key-objects.html#index-gpgme_005fuser_005fid_005ft)
#[derive(Copy, Clone)]
pub struct UserId<'key>(NonNull<ffi::gpgme_user_id_t>, PhantomData<&'key Key>);

unsafe impl Send for UserId<'_> {}
unsafe impl Sync for UserId<'_> {}

impl<'key> UserId<'key> {
    impl_wrapper!(ffi::gpgme_user_id_t, PhantomData);

    #[inline]
    pub fn id(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.id_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn id_raw(&self) -> Option<&'key CStr> {
        unsafe { (*self.as_raw()).uid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn name(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.name_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn name_raw(&self) -> Option<&'key CStr> {
        unsafe { (*self.as_raw()).name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn email(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.email_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn email_raw(&self) -> Option<&'key CStr> {
        unsafe { (*self.as_raw()).email.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn comment(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.comment_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn comment_raw(&self) -> Option<&'key CStr> {
        unsafe { (*self.as_raw()).comment.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn uidhash(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.uidhash_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn uidhash_raw(&self) -> Option<&'key CStr> {
        require_gpgme_ver! {
            (1, 14) => {
                unsafe { (*self.as_raw()).uidhash.as_ref().map(|s| CStr::from_ptr(s)) }
            } else {
                None
            }
        }
    }

    #[inline]
    pub fn address(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.address_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn address_raw(&self) -> Option<&'key CStr> {
        unsafe { (*self.as_raw()).address.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn validity(&self) -> Validity {
        unsafe { Validity::from_raw((*self.as_raw()).validity) }
    }

    #[inline]
    pub fn is_bad(&self) -> bool {
        self.is_revoked() || self.is_invalid()
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
    pub fn origin(&self) -> crate::KeyOrigin {
        unsafe { crate::KeyOrigin::from_raw((*self.as_raw()).origin()) }
    }

    require_gpgme_ver! {
        (1, 8) => {
            #[inline]
            pub fn last_update(&self) -> SystemTime {
                let timestamp = unsafe { (*self.as_raw()).last_update };
                UNIX_EPOCH + Duration::from_secs(timestamp.into())
            }
        }
    }

    #[inline]
    pub fn signature(&self, key: &Key) -> Option<UserIdSignature<'key>> {
        if key.protocol() != Protocol::OpenPgp {
            return None;
        }

        self.signatures()
            .filter(|s| {
                s.signer_key_id_raw() == key.id_raw()
                    && !(s.is_bad() || s.is_revocation())
                    && (s.status() == Error::NO_ERROR)
            })
            .max_by_key(|s| s.creation_time())
    }

    #[inline]
    pub fn signatures(&self) -> UserIdSignatures<'key> {
        unsafe { UserIdSignatures::from_list((*self.as_raw()).signatures) }
    }

    #[inline]
    pub fn tofu_info(&self) -> Option<crate::TofuInfo<'key>> {
        require_gpgme_ver! {
            (1,7) => {
                unsafe {
                    (*self.as_raw())
                        .tofu
                        .as_mut()
                        .map(|t| crate::TofuInfo::from_raw(t))
                }
            } else {
                None
            }
        }
    }
}

impl fmt::Debug for UserId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserId")
            .field("raw", &self.as_raw())
            .field("name", &self.name_raw())
            .field("email", &self.email_raw())
            .field("comment", &self.comment_raw())
            .field("validity", &self.validity())
            .field("revoked", &self.is_revoked())
            .field("invalid", &self.is_invalid())
            .field("origin", &self.origin())
            .field("tofu_info", &self.tofu_info())
            .field("signatures", &self.signatures())
            .finish()
    }
}

impl fmt::Display for UserId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            &*self
                .id_raw()
                .map(|s| s.to_string_lossy())
                .unwrap_or("".into()),
        )
    }
}

impl_list_iterator!(pub struct UserIds(UserId: ffi::gpgme_user_id_t));

#[derive(Debug)]
pub enum SignatureTrust {
    None,
    Partial,
    Complete,
}

/// Upstream documentation: [`gpgme_key_sig_t`](https://www.gnupg.org/documentation/manuals/gpgme/Key-objects.html#index-gpgme_005fkey_005fsig_005ft)
#[derive(Copy, Clone)]
pub struct UserIdSignature<'key>(NonNull<ffi::gpgme_key_sig_t>, PhantomData<&'key Key>);

unsafe impl Send for UserIdSignature<'_> {}
unsafe impl Sync for UserIdSignature<'_> {}

impl<'key> UserIdSignature<'key> {
    impl_wrapper!(ffi::gpgme_key_sig_t, PhantomData);

    #[inline]
    pub fn signer_key_id(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.signer_key_id_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn signer_key_id_raw(&self) -> Option<&'key CStr> {
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
    pub fn is_bad(&self) -> bool {
        self.is_expired() || self.is_invalid()
    }

    #[inline]
    pub fn is_revocation(&self) -> bool {
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
    pub fn signer_user_id(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.signer_user_id_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn signer_user_id_raw(&self) -> Option<&'key CStr> {
        unsafe { (*self.as_raw()).uid.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn signer_name(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.signer_name_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn signer_name_raw(&self) -> Option<&'key CStr> {
        unsafe { (*self.as_raw()).name.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn signer_email(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.signer_email_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn signer_email_raw(&self) -> Option<&'key CStr> {
        unsafe { (*self.as_raw()).email.as_ref().map(|s| CStr::from_ptr(s)) }
    }

    #[inline]
    pub fn signer_comment(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.signer_comment_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn signer_comment_raw(&self) -> Option<&'key CStr> {
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
    pub fn policy_url(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.policy_url_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn policy_url_raw(&self) -> Option<&'key CStr> {
        self.notations().find_map(|n| {
            if n.name_raw().is_none() {
                n.value_raw()
            } else {
                None
            }
        })
    }

    #[inline]
    pub fn remark(&self) -> Result<&'key str, Option<Utf8Error>> {
        self.remark_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn remark_raw(&self) -> Option<&'key CStr> {
        self.notations().find_map(|n| {
            if n.name() == Ok("rem@gnupg.org") {
                n.value_raw()
            } else {
                None
            }
        })
    }

    #[inline]
    pub fn notations(&self) -> SignatureNotations<'key> {
        unsafe { SignatureNotations::from_list((*self.as_raw()).notations) }
    }

    require_gpgme_ver! {
        (1, 16) => {
            #[inline]
            pub fn is_trust_signature(&self) -> bool {
                self.trust_depth() != 0
            }

            #[inline]
            pub fn trust_value(&self) -> SignatureTrust {
                let value = unsafe {
                    (*self.as_raw()).trust_value()
                };
                if !self.is_trust_signature() {
                    SignatureTrust::None
                } else if value >= 120 {
                    SignatureTrust::Complete
                } else {
                    SignatureTrust::Partial
                }
            }

            #[inline]
            pub fn trust_depth(&self) -> u8 {
                unsafe {
                    (*self.as_raw()).trust_depth()
                }
            }

            #[inline]
            pub fn trust_scope(&self) -> Result<&'key str, Option<Utf8Error>> {
                self.trust_scope_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
            }

            #[inline]
            pub fn trust_scope_raw(&self) -> Option<&'key CStr> {
                unsafe {
                    (*self.as_raw()).trust_scope.as_ref().map(|s| CStr::from_ptr(s))
                }
            }
        }
    }
}

impl fmt::Debug for UserIdSignature<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserIdSignature")
            .field("raw", &self.as_raw())
            .field("signer_key", &self.signer_key_id_raw())
            .field("signer", &self.signer_user_id_raw())
            .field("algorithm", &self.algorithm())
            .field("expired", &self.is_expired())
            .field("creation_time", &self.creation_time())
            .field("expiration_time", &self.expiration_time())
            .field("invalid", &self.is_invalid())
            .field("revoked", &self.is_revocation())
            .field("exportable", &self.is_exportable())
            .field("status", &self.status())
            .field("notations", &self.notations())
            .finish()
    }
}

impl_list_iterator!(pub struct UserIdSignatures(UserIdSignature: ffi::gpgme_key_sig_t));
