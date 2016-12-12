use std::ffi::{CStr, CString};
use std::{mem, ptr, result};
use std::str::Utf8Error;
use std::time::{SystemTime, UNIX_EPOCH};

use libc;
use conv::{UnwrapOrSaturate, ValueInto};
use ffi;

use {Data, EditHandler, Error, InteractHandler, IntoNativeString, Key, KeyListMode,
     PassphraseProvider, ProgressHandler, Protocol, Result, SignMode, StatusHandler, TofuPolicy,
     TrustItem};
use {callbacks, edit, error};
use engine::EngineInfo;
use notation::SignatureNotations;
use results;

/// A context for cryptographic operations
#[derive(Debug)]
pub struct Context(ffi::gpgme_ctx_t);

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { ffi::gpgme_release(self.0) }
    }
}

impl Context {
    impl_wrapper!(Context: ffi::gpgme_ctx_t);

    fn new() -> Result<Self> {
        ::init();
        unsafe {
            let mut ctx = ptr::null_mut();
            return_err!(ffi::gpgme_new(&mut ctx));
            Ok(Context::from_raw(ctx))
        }
    }

    pub fn from_protocol(proto: Protocol) -> Result<Self> {
        let ctx = try!(Context::new());
        unsafe {
            return_err!(ffi::gpgme_set_protocol(ctx.as_raw(), proto.raw()));
        }
        Ok(ctx)
    }

    pub fn protocol(&self) -> Protocol {
        unsafe { Protocol::from_raw(ffi::gpgme_get_protocol(self.0)) }
    }

    pub fn armor(&self) -> bool {
        unsafe { ffi::gpgme_get_armor(self.0) != 0 }
    }

    pub fn set_armor(&mut self, enabled: bool) {
        unsafe {
            ffi::gpgme_set_armor(self.0, if enabled { 1 } else { 0 });
        }
    }

    pub fn text_mode(&self) -> bool {
        unsafe { ffi::gpgme_get_textmode(self.0) != 0 }
    }

    pub fn set_text_mode(&mut self, enabled: bool) {
        unsafe {
            ffi::gpgme_set_textmode(self.0, if enabled { 1 } else { 0 });
        }
    }

    pub fn offline(&self) -> bool {
        unsafe { ffi::gpgme_get_offline(self.0) != 0 }
    }

    pub fn set_offline(&mut self, enabled: bool) {
        unsafe {
            ffi::gpgme_set_offline(self.0, if enabled { 1 } else { 0 });
        }
    }

    pub fn get_flag<S>(&self, name: S) -> result::Result<&str, Option<Utf8Error>>
    where S: IntoNativeString {
        self.get_flag_raw(name).map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn get_flag_raw<S>(&self, name: S) -> Option<&CStr> where S: IntoNativeString {
        let name = name.into_native();
        unsafe {
            ffi::gpgme_get_ctx_flag(self.0, name.as_ref().as_ptr())
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    pub fn set_flag<S1, S2>(&mut self, name: S1, value: S2) -> Result<()>
    where S1: IntoNativeString, S2: IntoNativeString {
        let name = name.into_native();
        let value = value.into_native();
        unsafe {
            return_err!(ffi::gpgme_set_ctx_flag(self.0,
                                                name.as_ref().as_ptr(),
                                                value.as_ref().as_ptr()));
        }
        Ok(())
    }

    pub fn engine_info(&self) -> EngineInfo<Context> {
        unsafe { EngineInfo::from_raw(ffi::gpgme_ctx_get_engine_info(self.0)) }
    }

    pub fn set_engine_path<S>(&self, path: S) -> Result<()> where S: IntoNativeString {
        let path = path.into_native();
        let home_dir = self.engine_info()
            .home_dir_raw()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null());
        unsafe {
            return_err!(ffi::gpgme_ctx_set_engine_info(self.0,
                                                       self.protocol().raw(),
                                                       path.as_ref().as_ptr(),
                                                       home_dir));
        }
        Ok(())
    }

    pub fn set_engine_home_dir<S>(&self, home_dir: S) -> Result<()> where S: IntoNativeString {
        let path = self.engine_info().path_raw().map(|s| s.as_ptr()).unwrap_or(ptr::null());
        let home_dir = home_dir.into_native();
        unsafe {
            return_err!(ffi::gpgme_ctx_set_engine_info(self.0,
                                                       self.protocol().raw(),
                                                       path,
                                                       home_dir.as_ref().as_ptr()));
        }
        Ok(())
    }

    pub fn set_engine_info<S1, S2>(&mut self, path: S1, home_dir: S2) -> Result<()>
    where S1: IntoNativeString, S2: IntoNativeString {
        let path = path.into_native();
        let home_dir = home_dir.into_native();
        unsafe {
            let path = path.as_ref().as_ptr();
            let home_dir = home_dir.as_ref().as_ptr();
            return_err!(ffi::gpgme_ctx_set_engine_info(self.0,
                                                       self.protocol().raw(),
                                                       path,
                                                       home_dir));
        }
        Ok(())
    }

    /// Uses the specified provider to handle passphrase requests for the duration of the
    /// closure.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io::prelude::*;
    ///
    /// use gpgme::{Context, PassphraseRequest, Protocol};
    ///
    /// let mut ctx = Context::from_protocol(Protocol::OpenPgp).unwrap();
    /// ctx.with_passphrase_provider(|_: PassphraseRequest, out: &mut Write| {
    ///     try!(out.write_all(b"some passphrase"));
    ///     Ok(())
    /// }, |mut ctx| {
    ///     // Do something with ctx requiring a passphrase, for example decryption
    /// });
    /// ```
    pub fn with_passphrase_provider<P, F, R>(&mut self, mut provider: P, f: F) -> R
    where P: PassphraseProvider, F: FnOnce(&mut Context) -> R {
        unsafe {
            let mut old = (None, ptr::null_mut());
            ffi::gpgme_get_passphrase_cb(self.0, &mut old.0, &mut old.1);
            ffi::gpgme_set_passphrase_cb(self.0,
                                         Some(callbacks::passphrase_cb::<P>),
                                         (&mut provider as *mut _) as *mut _);
            let _guard = callbacks::PassphraseProviderGuard {
                ctx: self.0,
                old: old,
            };
            f(self)
        }
    }

    pub fn with_progress_handler<H, F, R>(&mut self, mut handler: H, f: F) -> R
    where H: ProgressHandler, F: FnOnce(&mut Context) -> R {
        unsafe {
            let mut old = (None, ptr::null_mut());
            ffi::gpgme_get_progress_cb(self.0, &mut old.0, &mut old.1);
            ffi::gpgme_set_progress_cb(self.0,
                                       Some(callbacks::progress_cb::<H>),
                                       (&mut handler as *mut _) as *mut _);
            let _guard = callbacks::ProgressHandlerGuard {
                ctx: self.0,
                old: old,
            };
            f(self)
        }
    }

    pub fn with_status_handler<H, F, R>(&mut self, mut handler: H, f: F) -> R
    where H: StatusHandler, F: FnOnce(&mut Context) -> R {
        unsafe {
            let mut old = (None, ptr::null_mut());
            ffi::gpgme_get_status_cb(self.0, &mut old.0, &mut old.1);
            ffi::gpgme_set_status_cb(self.0,
                                     Some(callbacks::status_cb::<H>),
                                     (&mut handler as *mut _) as *mut _);
            let _guard = callbacks::StatusHandlerGuard {
                ctx: self.0,
                old: old,
            };
            f(self)
        }
    }

    pub fn find_trust_items<S: IntoNativeString>(&mut self, pattern: S, max_level: i32)
        -> Result<TrustItems> {
        let pattern = pattern.into_native();
        unsafe {
            return_err!(ffi::gpgme_op_trustlist_start(self.0,
                                                      pattern.as_ref().as_ptr(),
                                                      max_level.into()));
        }
        Ok(TrustItems { ctx: self })
    }

    pub fn key_list_mode(&self) -> KeyListMode {
        unsafe { ::KeyListMode::from_bits_truncate(ffi::gpgme_get_keylist_mode(self.0)) }
    }

    pub fn add_key_list_mode(&mut self, mask: KeyListMode) -> Result<()> {
        unsafe {
            let old = ffi::gpgme_get_keylist_mode(self.0);
            return_err!(ffi::gpgme_set_keylist_mode(self.0,
                                                    mask.bits() |
                                                    (old & !KeyListMode::all().bits())));
        }
        Ok(())
    }

    pub fn set_key_list_mode(&mut self, mode: KeyListMode) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_set_keylist_mode(self.0, mode.bits()));
        }
        Ok(())
    }

    pub fn keys(&mut self) -> Result<Keys> {
        Keys::new(self, None::<String>, false)
    }

    pub fn secret_keys(&mut self) -> Result<Keys> {
        Keys::new(self, None::<String>, true)
    }

    /// Returns the public key with the specified fingerprint, if such a key can
    /// be found. Otherwise, an error is returned.
    pub fn find_key<S: IntoNativeString>(&self, fingerprint: S) -> Result<Key> {
        let fingerprint = fingerprint.into_native();
        unsafe {
            let mut key = ptr::null_mut();
            return_err!(ffi::gpgme_get_key(self.0, fingerprint.as_ref().as_ptr(), &mut key, 0));
            Ok(Key::from_raw(key))
        }
    }

    /// Returns the secret key with the specified fingerprint, if such a key can
    /// be found. Otherwise, an error is returned.
    pub fn find_secret_key<S: IntoNativeString>(&self, fingerprint: S) -> Result<Key> {
        let fingerprint = fingerprint.into_native();
        unsafe {
            let mut key = ptr::null_mut();
            return_err!(ffi::gpgme_get_key(self.0, fingerprint.as_ref().as_ptr(), &mut key, 1));
            Ok(Key::from_raw(key))
        }
    }

    /// Returns an iterator for a list of all public keys matching one or more of the
    /// specified patterns.
    pub fn find_keys<I>(&mut self, patterns: I) -> Result<Keys>
    where I: IntoIterator, I::Item: IntoNativeString {
        Keys::new(self, patterns, false)
    }

    /// Returns an iterator for a list of all secret keys matching one or more of the
    /// specified patterns.
    pub fn find_secret_keys<I>(&mut self, patterns: I) -> Result<Keys>
    where I: IntoIterator, I::Item: IntoNativeString {
        Keys::new(self, patterns, true)
    }

    pub fn generate_key<S>(&mut self, params: S, public: Option<&mut Data>,
        secret: Option<&mut Data>)
        -> Result<results::KeyGenerationResult>
    where S: IntoNativeString {
        let params = params.into_native();
        let public = public.map_or(ptr::null_mut(), |d| d.as_raw());
        let secret = secret.map_or(ptr::null_mut(), |d| d.as_raw());
        unsafe {
            return_err!(ffi::gpgme_op_genkey(self.0, params.as_ref().as_ptr(), public, secret));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn create_key<S1, S2>(&mut self, userid: S1, algo: S2, expires: Option<SystemTime>,
        flags: ::CreateKeyFlags)
        -> Result<results::KeyGenerationResult>
    where S1: IntoNativeString, S2: IntoNativeString {
        let userid = userid.into_native();
        let algo = algo.into_native();
        let expires = expires.and_then(|e| e.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |e| e.as_secs().value_into().unwrap_or_saturate());

        unsafe {
            return_err!(ffi::gpgme_op_createkey(self.0,
                                                userid.as_ref().as_ptr(),
                                                algo.as_ref().as_ptr(),
                                                0,
                                                expires,
                                                ptr::null_mut(),
                                                flags.bits()));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn create_subkey<S>(&mut self, key: &Key, algo: S, expires: Option<SystemTime>,
        flags: ::CreateKeyFlags)
        -> Result<results::KeyGenerationResult>
    where S: IntoNativeString {
        let algo = algo.into_native();
        let expires = expires.and_then(|e| e.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |e| e.as_secs().value_into().unwrap_or_saturate());

        unsafe {
            return_err!(ffi::gpgme_op_createsubkey(self.0,
                                                   key.as_raw(),
                                                   algo.as_ref().as_ptr(),
                                                   0,
                                                   expires,
                                                   flags.bits()));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn add_uid<S>(&mut self, key: &Key, userid: S) -> Result<()> where S: IntoNativeString {
        let userid = userid.into_native();
        unsafe {
            return_err!(ffi::gpgme_op_adduid(self.0, key.as_raw(), userid.as_ref().as_ptr(), 0));
        }
        Ok(())
    }

    pub fn revoke_uid<S>(&mut self, key: &Key, userid: S) -> Result<()> where S: IntoNativeString {
        let userid = userid.into_native();
        unsafe {
            return_err!(ffi::gpgme_op_revuid(self.0, key.as_raw(), userid.as_ref().as_ptr(), 0));
        }
        Ok(())
    }

    pub fn sign_key<I>(&mut self, key: &Key, userids: I, expires: Option<SystemTime>) -> Result<()>
    where I: IntoIterator, I::Item: AsRef<[u8]> {
        self.sign_key_with_flags(key, userids, expires, ::KeySigningFlags::empty())
    }

    pub fn sign_key_with_flags<I>(&mut self, key: &Key, userids: I, expires: Option<SystemTime>,
        flags: ::KeySigningFlags)
        -> Result<()>
    where I: IntoIterator, I::Item: AsRef<[u8]> {
        let (userids, flags) = {
            let mut userids = userids.into_iter();
            match (userids.next(), userids.next()) {
                (Some(first), Some(second)) => {
                    (userids.fold([first.as_ref(), second.as_ref()].join(&b'\n'),
                                  |mut acc, x| {
                        acc.push(b'\n');
                        acc.extend_from_slice(x.as_ref());
                        acc
                    }),
                     ::KEY_SIGN_LFSEP | flags)
                }
                (Some(first), None) => (first.as_ref().to_owned(), flags),
                _ => panic!("no userids provided"),
            }
        };
        let userids = try!(CString::new(userids));
        let expires = expires.and_then(|e| e.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |e| e.as_secs().value_into().unwrap_or_saturate());
        unsafe {
            return_err!(ffi::gpgme_op_keysign(self.0,
                                              key.as_raw(),
                                              userids.as_ptr(),
                                              expires,
                                              flags.bits()));
        }
        Ok(())
    }

    pub fn change_key_tofu_policy(&mut self, key: &Key, policy: TofuPolicy) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_op_tofu_policy(self.0, key.as_raw(), policy.raw()));
        }
        Ok(())
    }

    // Only works with GPG >= 2.0.15
    pub fn change_key_passphrase(&mut self, key: &Key) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_op_passwd(self.0, key.as_raw(), 0));
        }
        Ok(())
    }

    pub fn edit_key<E: EditHandler>(&mut self, key: &Key, handler: E, data: &mut Data)
        -> Result<()> {
        unsafe {
            let mut wrapper = callbacks::EditHandlerWrapper {
                handler: handler,
                response: data,
            };
            return_err!(ffi::gpgme_op_edit(self.0,
                                           key.as_raw(),
                                           Some(callbacks::edit_cb::<E>),
                                           (&mut wrapper as *mut _) as *mut _,
                                           data.as_raw()));
        }
        Ok(())
    }

    pub fn edit_card_key<E: EditHandler>(&mut self, key: &Key, handler: E, data: &mut Data)
        -> Result<()> {
        unsafe {
            let mut wrapper = callbacks::EditHandlerWrapper {
                handler: handler,
                response: data,
            };
            return_err!(ffi::gpgme_op_card_edit(self.0,
                                                key.as_raw(),
                                                Some(callbacks::edit_cb::<E>),
                                                (&mut wrapper as *mut _) as *mut _,
                                                data.as_raw()));
        }
        Ok(())
    }

    pub fn edit_key_with<E: edit::Editor>(&mut self, key: &Key, editor: E, data: &mut Data)
        -> Result<()> {
        self.edit_key(key, edit::EditorWrapper::new(editor), data)
    }

    pub fn edit_card_key_with<E: edit::Editor>(&mut self, key: &Key, editor: E, data: &mut Data)
        -> Result<()> {
        self.edit_card_key(key, edit::EditorWrapper::new(editor), data)
    }

    pub fn interact<H: InteractHandler>(&mut self, key: &Key, handler: H, data: &mut Data)
        -> Result<()> {
        unsafe {
            let mut wrapper = callbacks::InteractHandlerWrapper {
                handler: handler,
                response: data,
            };
            return_err!(ffi::gpgme_op_interact(self.0,
                                               key.as_raw(),
                                               0,
                                               Some(callbacks::interact_cb::<H>),
                                               &mut wrapper as *mut _ as *mut _,
                                               data.as_raw()));
        }
        Ok(())
    }

    pub fn interact_with_card<H: InteractHandler>(&mut self, key: &Key, handler: H,
        data: &mut Data)
        -> Result<()> {
        unsafe {
            let mut wrapper = callbacks::InteractHandlerWrapper {
                handler: handler,
                response: data,
            };
            return_err!(ffi::gpgme_op_interact(self.0,
                                               key.as_raw(),
                                               ffi::GPGME_INTERACT_CARD,
                                               Some(callbacks::interact_cb::<H>),
                                               &mut wrapper as *mut _ as *mut _,
                                               data.as_raw()));
        }
        Ok(())
    }

    pub fn delete_key(&mut self, key: &Key) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_op_delete(self.0, key.as_raw(), 0));
        }
        Ok(())
    }

    pub fn delete_secret_key(&mut self, key: &Key) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_op_delete(self.0, key.as_raw(), 1));
        }
        Ok(())
    }

    pub fn import(&mut self, key_data: &mut Data) -> Result<results::ImportResult> {
        unsafe {
            return_err!(ffi::gpgme_op_import(self.0, key_data.as_raw()));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn import_keys<'k, I>(&mut self, keys: I) -> Result<results::ImportResult>
    where I: IntoIterator<Item = &'k Key> {
        let mut ptrs: Vec<_> = keys.into_iter().map(|k| k.as_raw()).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            return_err!(ffi::gpgme_op_import_keys(self.0, keys));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn export_all(&mut self, mode: ::ExportMode, data: Option<&mut Data>) -> Result<()> {
        self.export(None::<String>, mode, data)
    }

    pub fn export<I>(&mut self, patterns: I, mode: ::ExportMode, data: Option<&mut Data>)
        -> Result<()>
    where I: IntoIterator, I::Item: IntoNativeString {
        let data = data.map_or(ptr::null_mut(), |d| d.as_raw());
        let patterns: Vec<_> = patterns.into_iter().map(|s| s.into_native()).collect();
        let mut patterns: Vec<_> = patterns.iter().map(|s| s.as_ref().as_ptr()).collect();
        let ptr = if !patterns.is_empty() {
            patterns.push(ptr::null());
            patterns.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            return_err!(ffi::gpgme_op_export_ext(self.0, ptr, mode.bits(), data));
        }
        Ok(())
    }

    pub fn export_keys<'k, I>(&mut self, keys: I, mode: ::ExportMode, data: Option<&mut Data>)
        -> Result<()>
    where I: IntoIterator<Item = &'k Key> {
        let data = data.map_or(ptr::null_mut(), |d| d.as_raw());
        let mut ptrs: Vec<_> = keys.into_iter().map(|k| k.as_raw()).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            return_err!(ffi::gpgme_op_export_keys(self.0, keys, mode.bits(), data));
        }
        Ok(())
    }

    pub fn clear_sender(&mut self) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_set_sender(self.0, ptr::null()));
        }
        Ok(())
    }

    pub fn set_sender<S: IntoNativeString>(&mut self, sender: S) -> Result<()> {
        let sender = sender.into_native();
        unsafe {
            return_err!(ffi::gpgme_set_sender(self.0, sender.as_ref().as_ptr()));
        }
        Ok(())
    }

    pub fn sender(&self) -> result::Result<&str, Option<Utf8Error>> {
        match self.sender_raw() {
            Some(s) => s.to_str().map_err(Some),
            None => Err(None),
        }
    }

    pub fn sender_raw(&self) -> Option<&CStr> {
        unsafe { ffi::gpgme_get_sender(self.0).as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn clear_signers(&mut self) {
        unsafe { ffi::gpgme_signers_clear(self.0) }
    }

    pub fn add_signer(&mut self, key: &Key) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_signers_add(self.0, key.as_raw()));
        }
        Ok(())
    }

    pub fn signers(&self) -> Signers {
        Signers {
            ctx: self,
            current: Some(0),
        }
    }

    pub fn clear_signature_notations(&mut self) {
        unsafe {
            ffi::gpgme_sig_notation_clear(self.0);
        }
    }

    pub fn add_signature_notation<S1, S2>(&mut self, name: S1, value: S2,
        flags: ::SignatureNotationFlags)
        -> Result<()>
    where S1: IntoNativeString, S2: IntoNativeString {
        let name = name.into_native();
        let value = value.into_native();
        unsafe {
            return_err!(ffi::gpgme_sig_notation_add(self.0,
                                                    name.as_ref().as_ptr(),
                                                    value.as_ref().as_ptr(),
                                                    flags.bits()));
        }
        Ok(())
    }

    pub fn add_signature_policy_url<S>(&mut self, url: S, critical: bool) -> Result<()>
    where S: IntoNativeString {
        let url = url.into_native();
        unsafe {
            let critical = if critical {
                ffi::GPGME_SIG_NOTATION_CRITICAL
            } else {
                0
            };
            return_err!(ffi::gpgme_sig_notation_add(self.0,
                                                    ptr::null(),
                                                    url.as_ref().as_ptr(),
                                                    critical));
        }
        Ok(())
    }

    pub fn signature_policy_url(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.signature_policy_url_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn signature_policy_url_raw(&self) -> Option<&CStr> {
        unsafe {
            let mut notation = ffi::gpgme_sig_notation_get(self.0);
            while !notation.is_null() {
                if (*notation).name.is_null() {
                    return (*notation).value.as_ref().map(|s| CStr::from_ptr(s));
                }
                notation = (*notation).next;
            }
            None
        }
    }

    pub fn signature_notations(&self) -> SignatureNotations<Context> {
        unsafe { SignatureNotations::from_list(ffi::gpgme_sig_notation_get(self.0)) }
    }

    pub fn sign(&mut self, mode: ::SignMode, plain: &mut Data, signature: &mut Data)
        -> Result<results::SigningResult> {
        unsafe {
            return_err!(ffi::gpgme_op_sign(self.0, plain.as_raw(), signature.as_raw(), mode.raw()));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn sign_clear(&mut self, plain: &mut Data, signed: &mut Data)
        -> Result<results::SigningResult> {
        self.sign(SignMode::Clear, plain, signed)
    }

    pub fn sign_detached(&mut self, plain: &mut Data, signature: &mut Data)
        -> Result<results::SigningResult> {
        self.sign(SignMode::Detached, plain, signature)
    }

    pub fn sign_normal(&mut self, plain: &mut Data, signed: &mut Data)
        -> Result<results::SigningResult> {
        self.sign(SignMode::Normal, plain, signed)
    }

    pub fn verify(&mut self, signature: &mut Data, signed: Option<&mut Data>,
        plain: Option<&mut Data>)
        -> Result<results::VerificationResult> {
        let signed = signed.map_or(ptr::null_mut(), |d| d.as_raw());
        let plain = plain.map_or(ptr::null_mut(), |d| d.as_raw());
        unsafe {
            return_err!(ffi::gpgme_op_verify(self.0, signature.as_raw(), signed, plain));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn verify_detached(&mut self, signature: &mut Data, signed: &mut Data)
        -> Result<results::VerificationResult> {
        self.verify(signature, Some(signed), None)
    }

    pub fn verify_opaque(&mut self, signature: &mut Data, plain: &mut Data)
        -> Result<results::VerificationResult> {
        self.verify(signature, None, Some(plain))
    }

    /// Encrypts a message for the specified recipients.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use gpgme::{Context, Data, Protocol};
    ///
    /// let mut ctx = Context::from_protocol(Protocol::OpenPgp).unwrap();
    /// let key = ctx.find_key("some pattern").unwrap();
    /// let (mut plaintext, mut ciphertext) = (Data::new().unwrap(), Data::new().unwrap());
    /// ctx.encrypt(Some(&key), &mut plaintext, &mut ciphertext).unwrap();
    /// ```
    pub fn encrypt<'k, I>(&mut self, recp: I, plaintext: &mut Data, ciphertext: &mut Data)
        -> Result<results::EncryptionResult>
    where I: IntoIterator<Item = &'k Key> {
        self.encrypt_with_flags(recp, ::EncryptFlags::empty(), plaintext, ciphertext)
    }

    pub fn encrypt_with_flags<'k, I>(&mut self, recp: I, flags: ::EncryptFlags,
        plaintext: &mut Data, ciphertext: &mut Data)
        -> Result<results::EncryptionResult>
    where I: IntoIterator<Item = &'k Key> {
        let mut ptrs: Vec<_> = recp.into_iter().map(|k| k.as_raw()).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            return_err!(ffi::gpgme_op_encrypt(self.0,
                                              keys,
                                              flags.bits(),
                                              plaintext.as_raw(),
                                              ciphertext.as_raw()));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn encrypt_symmetric(&mut self, plaintext: &mut Data, ciphertext: &mut Data) -> Result<()> {
        self.encrypt_symmetric_with_flags(::EncryptFlags::empty(), plaintext, ciphertext)
    }

    pub fn encrypt_symmetric_with_flags(&mut self, flags: ::EncryptFlags, plaintext: &mut Data,
        ciphertext: &mut Data)
        -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_op_encrypt(self.0,
                                              ptr::null_mut(),
                                              flags.bits(),
                                              plaintext.as_raw(),
                                              ciphertext.as_raw()));
        }
        Ok(())
    }

    /// Encrypts and signs a message for the specified recipients.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use gpgme::{Context, Data, Protocol};
    ///
    /// let mut ctx = Context::from_protocol(Protocol::OpenPgp).unwrap();
    /// let key = ctx.find_key("some pattern").unwrap();
    /// let (mut plaintext, mut ciphertext) = (Data::new().unwrap(), Data::new().unwrap());
    /// ctx.sign_and_encrypt(Some(&key), &mut plaintext, &mut ciphertext).unwrap();
    /// ```
    pub fn sign_and_encrypt<'k, I>(
        &mut self, recp: I, plaintext: &mut Data, ciphertext: &mut Data)
        -> Result<(results::EncryptionResult, results::SigningResult)>
    where I: IntoIterator<Item = &'k Key> {
        self.sign_and_encrypt_with_flags(recp, ::EncryptFlags::empty(), plaintext, ciphertext)
    }

    pub fn sign_and_encrypt_with_flags<'k, I>(
        &mut self, recp: I, flags: ::EncryptFlags, plaintext: &mut Data, ciphertext: &mut Data)
        -> Result<(results::EncryptionResult, results::SigningResult)>
    where I: IntoIterator<Item = &'k Key> {
        let mut ptrs: Vec<_> = recp.into_iter().map(|k| k.as_raw()).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            return_err!(ffi::gpgme_op_encrypt_sign(self.0,
                                                   keys,
                                                   flags.bits(),
                                                   plaintext.as_raw(),
                                                   ciphertext.as_raw()))
        }
        Ok((self.get_result().unwrap(), self.get_result().unwrap()))
    }

    /// Decrypts a message.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use gpgme::{Context, Data, Protocol};
    ///
    /// let mut ctx = Context::from_protocol(Protocol::OpenPgp).unwrap();
    /// let mut cipher = Data::load("some file").unwrap();
    /// let mut plain = Data::new().unwrap();
    /// ctx.decrypt(&mut cipher, &mut plain).unwrap();
    /// ```
    pub fn decrypt(&mut self, ciphertext: &mut Data, plaintext: &mut Data)
        -> Result<results::DecryptionResult> {
        unsafe {
            return_err!(ffi::gpgme_op_decrypt(self.0, ciphertext.as_raw(), plaintext.as_raw()));
        }
        Ok(self.get_result().unwrap())
    }

    /// Decrypts and verifies a message.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use gpgme::{Context, Data, Protocol};
    ///
    /// let mut ctx = Context::from_protocol(Protocol::OpenPgp).unwrap();
    /// let mut cipher = Data::load("some file").unwrap();
    /// let mut plain = Data::new().unwrap();
    /// ctx.decrypt_and_verify(&mut cipher, &mut plain).unwrap();
    /// ```
    pub fn decrypt_and_verify(
        &mut self, ciphertext: &mut Data, plaintext: &mut Data)
        -> Result<(results::DecryptionResult, results::VerificationResult)> {
        unsafe {
            return_err!(ffi::gpgme_op_decrypt_verify(self.0,
                                                     ciphertext.as_raw(),
                                                     plaintext.as_raw()))
        }
        Ok((self.get_result().unwrap(), self.get_result().unwrap()))
    }

    fn get_result<R: ::OpResult>(&self) -> Option<R> {
        R::from_context(self)
    }
}

#[derive(Debug)]
pub struct Keys<'a> {
    ctx: &'a mut Context,
}

impl<'a> Keys<'a> {
    fn new<I>(ctx: &mut Context, patterns: I, secret_only: bool) -> Result<Keys>
    where I: IntoIterator, I::Item: IntoNativeString {
        let patterns: Vec<_> = patterns.into_iter().map(|s| s.into_native()).collect();
        let mut patterns: Vec<_> = patterns.iter().map(|s| s.as_ref().as_ptr()).collect();
        let ptr = if !patterns.is_empty() {
            patterns.push(ptr::null());
            patterns.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            return_err!(ffi::gpgme_op_keylist_ext_start(ctx.as_raw(),
                                                        ptr,
                                                        if secret_only { 1 } else { 0 },
                                                        0));
        }
        Ok(Keys { ctx: ctx })
    }

    #[inline]
    pub fn finish(self) -> Result<results::KeyListResult> {
        let ctx = self.ctx as *mut Context;
        mem::forget(self);
        unsafe {
            return_err!(ffi::gpgme_op_keylist_end((*ctx).as_raw()));
            Ok((*ctx).get_result().unwrap())
        }
    }
}

impl<'a> Drop for Keys<'a> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_op_keylist_end(self.ctx.as_raw());
        }
    }
}

impl<'a> Iterator for Keys<'a> {
    type Item = Result<Key>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let mut key = ptr::null_mut();
            let result = ffi::gpgme_op_keylist_next(self.ctx.as_raw(), &mut key);
            if ffi::gpgme_err_code(result) != error::GPG_ERR_EOF {
                if result == 0 {
                    Some(Ok(Key::from_raw(key)))
                } else {
                    Some(Err(Error::new(result)))
                }
            } else {
                None
            }
        }
    }
}

#[derive(Debug)]
pub struct TrustItems<'a> {
    ctx: &'a mut Context,
}

impl<'a> TrustItems<'a> {
    #[inline]
    pub fn finish(self) -> Result<()> {
        let ctx = self.ctx as *mut Context;
        mem::forget(self);
        unsafe {
            return_err!(ffi::gpgme_op_trustlist_end((*ctx).as_raw()));
        }
        Ok(())
    }
}

impl<'a> Drop for TrustItems<'a> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_op_trustlist_end(self.ctx.as_raw());
        }
    }
}

impl<'a> Iterator for TrustItems<'a> {
    type Item = Result<TrustItem>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let mut trust_item = ptr::null_mut();
            let result = ffi::gpgme_op_trustlist_next(self.ctx.as_raw(), &mut trust_item);
            if ffi::gpgme_err_code(result) != error::GPG_ERR_EOF {
                if result == 0 {
                    Some(Ok(TrustItem::from_raw(trust_item)))
                } else {
                    Some(Err(Error::new(result)))
                }
            } else {
                None
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Signers<'a> {
    ctx: &'a Context,
    current: Option<libc::c_int>,
}

impl<'a> Iterator for Signers<'a> {
    type Item = Key;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            self.current.and_then(|x| match ffi::gpgme_signers_enum(self.ctx.as_raw(), x)
                .as_mut() {
                Some(key) => {
                    self.current = x.checked_add(1);
                    Some(Key::from_raw(key))
                }
                _ => {
                    self.current = None;
                    None
                }
            })
        }
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.current = self.current
            .and_then(|x| n.value_into().ok().and_then(|n| x.checked_add(n)));
        self.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.current.map_or((0, Some(0)), |c| {
            let count = unsafe {
                (ffi::gpgme_signers_count(self.ctx.as_raw()) - c as libc::c_uint).value_into()
            };
            (count.unwrap_or_saturate(), count.ok())
        })
    }

    #[inline]
    fn count(self) -> usize {
        self.size_hint().0
    }
}
