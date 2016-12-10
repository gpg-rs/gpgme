use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::mem;
use std::ptr;
use std::result;
use std::str::Utf8Error;

use libc;
use ffi;

use {IntoNativeString, Protocol, Token, Wrapper};
use error::{self, Error, Result};
use engine::{EngineInfo, EngineInfoIter};
use data::Data;
use keys::Key;
use keys::TofuPolicy;
use trust::TrustItem;
use notation::{self, SignatureNotationIter};
use edit;
use ops;
use utils::FdWriter;

/// A context for cryptographic operations
pub struct Context {
    raw: ffi::gpgme_ctx_t,
}

impl Context {
    pub fn new(_: Token) -> Result<Self> {
        unsafe {
            let mut ctx = ptr::null_mut();
            return_err!(ffi::gpgme_new(&mut ctx));
            Ok(Context::from_raw(ctx))
        }
    }

    pub fn get_flag<S>(&self, name: S) -> result::Result<&str, Option<Utf8Error>>
    where S: IntoNativeString {
        self.get_flag_raw(name).map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn get_flag_raw<S>(&self, name: S) -> Option<&CStr> where S: IntoNativeString {
        let name = name.into_native();
        unsafe {
            ffi::gpgme_get_ctx_flag(self.raw, name.as_ref().as_ptr())
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    pub fn set_flag<S1, S2>(&mut self, name: S1, value: S2) -> Result<()>
    where S1: IntoNativeString, S2: IntoNativeString {
        let name = name.into_native();
        let value = value.into_native();
        unsafe {
            return_err!(ffi::gpgme_set_ctx_flag(self.raw,
                                                name.as_ref().as_ptr(),
                                                value.as_ref().as_ptr()));
        }
        Ok(())
    }

    pub fn has_armor(&self) -> bool {
        unsafe { ffi::gpgme_get_armor(self.raw) != 0 }
    }

    pub fn set_armor(&mut self, enabled: bool) {
        unsafe {
            ffi::gpgme_set_armor(self.raw, enabled as libc::c_int);
        }
    }

    pub fn text_mode(&self) -> bool {
        unsafe { ffi::gpgme_get_textmode(self.raw) != 0 }
    }

    pub fn set_text_mode(&mut self, enabled: bool) {
        unsafe {
            ffi::gpgme_set_textmode(self.raw, enabled as libc::c_int);
        }
    }

    pub fn protocol(&self) -> Protocol {
        unsafe { Protocol::from_raw(ffi::gpgme_get_protocol(self.raw)) }
    }

    pub fn set_protocol(&mut self, proto: Protocol) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_set_protocol(self.raw, proto.raw()));
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
    /// use gpgme::context::PassphraseRequest;
    ///
    /// let mut ctx = gpgme::create_context().unwrap();
    /// ctx.with_passphrase_handler(|_: PassphraseRequest, out: &mut Write| {
    ///     try!(out.write_all(b"some passphrase"));
    ///     Ok(())
    /// }, |mut ctx| {
    ///     // Do something with ctx requiring a passphrase, for example decryption
    /// });
    /// ```
    pub fn with_passphrase_handler<H, F, R>(&mut self, mut handler: H, f: F) -> R
    where H: PassphraseHandler, F: FnOnce(&mut Context) -> R {
        unsafe {
            let mut old = (None, ptr::null_mut());
            ffi::gpgme_get_passphrase_cb(self.raw, &mut old.0, &mut old.1);
            ffi::gpgme_set_passphrase_cb(self.raw,
                                         Some(passphrase_callback::<H>),
                                         (&mut handler as *mut _) as *mut _);
            let _guard = PassphraseHandlerGuard {
                ctx: self.raw,
                old: old,
            };
            f(self)
        }
    }

    pub fn with_progress_handler<H, F, R>(&mut self, mut handler: H, f: F) -> R
    where H: ProgressHandler, F: FnOnce(&mut Context) -> R {
        unsafe {
            let mut old = (None, ptr::null_mut());
            ffi::gpgme_get_progress_cb(self.raw, &mut old.0, &mut old.1);
            ffi::gpgme_set_progress_cb(self.raw,
                                       Some(progress_callback::<H>),
                                       (&mut handler as *mut _) as *mut _);
            let _guard = ProgressHandlerGuard {
                ctx: self.raw,
                old: old,
            };
            f(self)
        }
    }

    pub fn with_status_handler<H, F, R>(&mut self, mut handler: H, f: F) -> R
    where H: StatusHandler, F: FnOnce(&mut Context) -> R {
        unsafe {
            let mut old = (None, ptr::null_mut());
            ffi::gpgme_get_status_cb(self.raw, &mut old.0, &mut old.1);
            ffi::gpgme_set_status_cb(self.raw,
                                     Some(status_callback::<H>),
                                     (&mut handler as *mut _) as *mut _);
            let _guard = StatusHandlerGuard {
                ctx: self.raw,
                old: old,
            };
            f(self)
        }
    }

    pub fn engine_info(&self) -> EngineInfoIter<Context> {
        unsafe { EngineInfoIter::from_list(ffi::gpgme_ctx_get_engine_info(self.raw)) }
    }

    pub fn get_engine_info(&self, proto: Protocol) -> Option<EngineInfo<Context>> {
        self.engine_info().find(|info| info.protocol() == proto)
    }

    pub fn set_engine_path<S>(&self, proto: Protocol, path: S) -> Result<()>
    where S: IntoNativeString {
        let path = path.into_native();
        unsafe {
            return_err!(ffi::gpgme_ctx_set_engine_info(self.raw,
                                                       proto.raw(),
                                                       path.as_ref().as_ptr(),
                                                       ptr::null()));
        }
        Ok(())
    }

    pub fn set_engine_home_dir<S>(&self, proto: Protocol, home_dir: S) -> Result<()>
    where S: IntoNativeString {
        let home_dir = home_dir.into_native();
        unsafe {
            return_err!(ffi::gpgme_ctx_set_engine_info(self.raw,
                                                       proto.raw(),
                                                       ptr::null(),
                                                       home_dir.as_ref().as_ptr()));
        }
        Ok(())
    }

    pub fn set_engine_info<S1, S2>(&mut self, proto: Protocol, path: S1, home_dir: S2) -> Result<()>
    where S1: IntoNativeString, S2: IntoNativeString {
        let path = path.into_native();
        let home_dir = home_dir.into_native();
        unsafe {
            let path = path.as_ref().as_ptr();
            let home_dir = home_dir.as_ref().as_ptr();
            return_err!(ffi::gpgme_ctx_set_engine_info(self.raw, proto.raw(), path, home_dir));
        }
        Ok(())
    }

    pub fn find_trust_items<S: IntoNativeString>(&mut self, pattern: S, max_level: i32)
        -> Result<TrustItems> {
        let pattern = pattern.into_native();
        unsafe {
            return_err!(ffi::gpgme_op_trustlist_start(self.raw,
                                                      pattern.as_ref().as_ptr(),
                                                      max_level.into()));
        }
        Ok(TrustItems { ctx: self })
    }

    pub fn offline(&self) -> bool {
        unsafe { ffi::gpgme_get_offline(self.raw) != 0 }
    }

    pub fn set_offline(&mut self, enabled: bool) {
        unsafe {
            ffi::gpgme_set_offline(self.raw, if enabled { 1 } else { 0 });
        }
    }

    pub fn key_list_mode(&self) -> ops::KeyListMode {
        unsafe { ops::KeyListMode::from_bits_truncate(ffi::gpgme_get_keylist_mode(self.raw)) }
    }

    pub fn set_key_list_mode(&mut self, mask: ops::KeyListMode) -> Result<()> {
        unsafe {
            let old = ffi::gpgme_get_keylist_mode(self.raw);
            return_err!(ffi::gpgme_set_keylist_mode(self.raw,
                                                    mask.bits() |
                                                    (old & !ops::KeyListMode::all().bits())));
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
            return_err!(ffi::gpgme_get_key(self.raw, fingerprint.as_ref().as_ptr(), &mut key, 0));
            Ok(Key::from_raw(key))
        }
    }

    /// Returns the secret key with the specified fingerprint, if such a key can
    /// be found. Otherwise, an error is returned.
    pub fn find_secret_key<S: IntoNativeString>(&self, fingerprint: S) -> Result<Key> {
        let fingerprint = fingerprint.into_native();
        unsafe {
            let mut key = ptr::null_mut();
            return_err!(ffi::gpgme_get_key(self.raw, fingerprint.as_ref().as_ptr(), &mut key, 1));
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
        -> Result<ops::KeyGenerateResult>
    where S: IntoNativeString {
        let params = params.into_native();
        let public = public.map_or(ptr::null_mut(), |d| d.as_raw());
        let secret = secret.map_or(ptr::null_mut(), |d| d.as_raw());
        unsafe {
            return_err!(ffi::gpgme_op_genkey(self.raw, params.as_ref().as_ptr(), public, secret));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn create_key<S1, S2>(&mut self, userid: S1, algo: S2, expires: Option<u32>,
        flags: ops::CreateKeyFlags)
        -> Result<ops::KeyGenerateResult>
    where S1: IntoNativeString, S2: IntoNativeString {
        let userid = userid.into_native();
        let algo = algo.into_native();
        unsafe {
            return_err!(ffi::gpgme_op_createkey(self.raw,
                                                userid.as_ref().as_ptr(),
                                                algo.as_ref().as_ptr(),
                                                0,
                                                expires.unwrap_or(0).into(),
                                                ptr::null_mut(),
                                                flags.bits()));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn create_subkey<S>(&mut self, key: &Key, algo: S, expires: Option<u32>,
        flags: ops::CreateKeyFlags)
        -> Result<ops::KeyGenerateResult>
    where S: IntoNativeString {
        let algo = algo.into_native();
        unsafe {
            return_err!(ffi::gpgme_op_createsubkey(self.raw,
                                                   key.as_raw(),
                                                   algo.as_ref().as_ptr(),
                                                   0,
                                                   expires.unwrap_or(0).into(),
                                                   flags.bits()));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn add_uid<S>(&mut self, key: &Key, userid: S) -> Result<()> where S: IntoNativeString {
        let userid = userid.into_native();
        unsafe {
            return_err!(ffi::gpgme_op_adduid(self.raw, key.as_raw(), userid.as_ref().as_ptr(), 0));
        }
        Ok(())
    }

    pub fn revoke_uid<S>(&mut self, key: &Key, userid: S) -> Result<()> where S: IntoNativeString {
        let userid = userid.into_native();
        unsafe {
            return_err!(ffi::gpgme_op_revuid(self.raw, key.as_raw(), userid.as_ref().as_ptr(), 0));
        }
        Ok(())
    }

    pub fn sign_key<I>(&mut self, key: &Key, userids: I, expires: Option<u32>) -> Result<()>
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
                     ffi::GPGME_KEYSIGN_LFSEP)
                }
                (Some(first), None) => (first.as_ref().to_owned(), 0),
                _ => panic!("no userids provided"),
            }
        };
        let userids = try!(CString::new(userids));
        unsafe {
            return_err!(ffi::gpgme_op_keysign(self.raw,
                                              key.as_raw(),
                                              userids.as_ptr(),
                                              expires.unwrap_or(0).into(),
                                              flags));
        }
        Ok(())
    }

    pub fn sign_key_with_flags<I>(&mut self, key: &Key, userids: I, expires: Option<u32>,
        flags: ops::KeySignFlags)
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
                     ops::KEY_SIGN_LFSEP | flags)
                }
                (Some(first), None) => (first.as_ref().to_owned(), flags),
                _ => panic!("no userids provided"),
            }
        };
        let userids = try!(CString::new(userids));
        unsafe {
            return_err!(ffi::gpgme_op_keysign(self.raw,
                                              key.as_raw(),
                                              userids.as_ptr(),
                                              expires.unwrap_or(0).into(),
                                              flags.bits()));
        }
        Ok(())
    }

    pub fn change_key_tofu_policy(&mut self, key: &Key, policy: TofuPolicy) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_op_tofu_policy(self.raw, key.as_raw(), policy.raw()));
        }
        Ok(())
    }

    // Only works with GPG >= 2.0.15
    pub fn change_key_passphrase(&mut self, key: &Key) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_op_passwd(self.raw, key.as_raw(), 0));
        }
        Ok(())
    }


    pub fn edit_card_key<E: EditHandler>(&mut self, key: &Key, handler: E, data: &mut Data)
        -> Result<()> {
        unsafe {
            let mut wrapper = EditHandlerWrapper {
                handler: handler,
                response: data,
            };
            return_err!(ffi::gpgme_op_card_edit(self.raw,
                                                key.as_raw(),
                                                Some(edit_callback::<E>),
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
            let mut wrapper = InteractHandlerWrapper {
                handler: handler,
                response: data,
            };
            return_err!(ffi::gpgme_op_interact(self.raw,
                                               key.as_raw(),
                                               0,
                                               Some(interact_callback::<H>),
                                               &mut wrapper as *mut _ as *mut _,
                                               data.as_raw()));
        }
        Ok(())
    }

    pub fn interact_with_card<H: InteractHandler>(&mut self, key: &Key, handler: H,
        data: &mut Data)
        -> Result<()> {
        unsafe {
            let mut wrapper = InteractHandlerWrapper {
                handler: handler,
                response: data,
            };
            return_err!(ffi::gpgme_op_interact(self.raw,
                                               key.as_raw(),
                                               ffi::GPGME_INTERACT_CARD,
                                               Some(interact_callback::<H>),
                                               &mut wrapper as *mut _ as *mut _,
                                               data.as_raw()));
        }
        Ok(())
    }

    pub fn delete_key(&mut self, key: &Key) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_op_delete(self.raw, key.as_raw(), 0));
        }
        Ok(())
    }

    pub fn delete_secret_key(&mut self, key: &Key) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_op_delete(self.raw, key.as_raw(), 1));
        }
        Ok(())
    }

    pub fn import(&mut self, key_data: &mut Data) -> Result<ops::ImportResult> {
        unsafe {
            return_err!(ffi::gpgme_op_import(self.raw, key_data.as_raw()));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn import_keys<'k, I>(&mut self, keys: I) -> Result<ops::ImportResult>
    where I: IntoIterator<Item = &'k Key> {
        let mut ptrs: Vec<_> = keys.into_iter().map(|k| k.as_raw()).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            return_err!(ffi::gpgme_op_import_keys(self.raw, keys));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn export_all(&mut self, mode: ops::ExportMode, data: Option<&mut Data>) -> Result<()> {
        self.export(None::<String>, mode, data)
    }

    pub fn export<I>(&mut self, patterns: I, mode: ops::ExportMode, data: Option<&mut Data>)
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
            return_err!(ffi::gpgme_op_export_ext(self.raw, ptr, mode.bits(), data));
        }
        Ok(())
    }

    pub fn export_keys<'k, I>(&mut self, keys: I, mode: ops::ExportMode, data: Option<&mut Data>)
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
            return_err!(ffi::gpgme_op_export_keys(self.raw, keys, mode.bits(), data));
        }
        Ok(())
    }

    pub fn edit_key<E: EditHandler>(&mut self, key: &Key, handler: E, data: &mut Data)
        -> Result<()> {
        unsafe {
            let mut wrapper = EditHandlerWrapper {
                handler: handler,
                response: data,
            };
            return_err!(ffi::gpgme_op_edit(self.raw,
                                           key.as_raw(),
                                           Some(edit_callback::<E>),
                                           (&mut wrapper as *mut _) as *mut _,
                                           data.as_raw()));
        }
        Ok(())
    }

    pub fn clear_sender(&mut self) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_set_sender(self.raw, ptr::null()));
        }
        Ok(())
    }

    pub fn set_sender<S: IntoNativeString>(&mut self, sender: S) -> Result<()> {
        let sender = sender.into_native();
        unsafe {
            return_err!(ffi::gpgme_set_sender(self.raw, sender.as_ref().as_ptr()));
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
        unsafe { ffi::gpgme_get_sender(self.raw).as_ref().map(|s| CStr::from_ptr(s)) }
    }

    pub fn clear_signers(&mut self) {
        unsafe { ffi::gpgme_signers_clear(self.raw) }
    }

    pub fn add_signer(&mut self, key: &Key) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_signers_add(self.raw, key.as_raw()));
        }
        Ok(())
    }

    pub fn signers_count(&self) -> u32 {
        unsafe { ffi::gpgme_signers_count(self.raw).into() }
    }

    pub fn signers(&self) -> SignersIter {
        SignersIter {
            ctx: self,
            current: Some(0),
        }
    }

    pub fn clear_notations(&mut self) {
        unsafe {
            ffi::gpgme_sig_notation_clear(self.raw);
        }
    }

    pub fn add_notation<S1, S2>(&mut self, name: S1, value: S2, flags: notation::Flags)
        -> Result<()>
    where S1: IntoNativeString, S2: IntoNativeString {
        let name = name.into_native();
        let value = value.into_native();
        unsafe {
            return_err!(ffi::gpgme_sig_notation_add(self.raw,
                                                    name.as_ref().as_ptr(),
                                                    value.as_ref().as_ptr(),
                                                    flags.bits()));
        }
        Ok(())
    }

    pub fn add_policy_url<S: IntoNativeString>(&mut self, url: S, critical: bool) -> Result<()> {
        let url = url.into_native();
        unsafe {
            let critical = if critical {
                ffi::GPGME_SIG_NOTATION_CRITICAL
            } else {
                0
            };
            return_err!(ffi::gpgme_sig_notation_add(self.raw,
                                                    ptr::null(),
                                                    url.as_ref().as_ptr(),
                                                    critical));
        }
        Ok(())
    }

    pub fn notations(&self) -> SignatureNotationIter<Context> {
        unsafe { SignatureNotationIter::from_list(ffi::gpgme_sig_notation_get(self.raw)) }
    }

    pub fn sign(&mut self, mode: ops::SignMode, plain: &mut Data, signature: &mut Data)
        -> Result<ops::SignResult> {
        unsafe {
            return_err!(ffi::gpgme_op_sign(self.raw,
                                           plain.as_raw(),
                                           signature.as_raw(),
                                           mode.raw()));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn sign_clear(&mut self, plain: &mut Data, signed: &mut Data) -> Result<ops::SignResult> {
        self.sign(ops::SIGN_MODE_CLEAR, plain, signed)
    }

    pub fn sign_detached(&mut self, plain: &mut Data, signature: &mut Data)
        -> Result<ops::SignResult> {
        self.sign(ops::SIGN_MODE_DETACH, plain, signature)
    }

    pub fn sign_normal(&mut self, plain: &mut Data, signed: &mut Data) -> Result<ops::SignResult> {
        self.sign(ops::SIGN_MODE_NORMAL, plain, signed)
    }

    pub fn verify(&mut self, signature: &mut Data, signed: Option<&mut Data>,
        plain: Option<&mut Data>)
        -> Result<ops::VerifyResult> {
        let signed = signed.map_or(ptr::null_mut(), |d| d.as_raw());
        let plain = plain.map_or(ptr::null_mut(), |d| d.as_raw());
        unsafe {
            return_err!(ffi::gpgme_op_verify(self.raw, signature.as_raw(), signed, plain));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn verify_detached(&mut self, signature: &mut Data, signed: &mut Data)
        -> Result<ops::VerifyResult> {
        self.verify(signature, Some(signed), None)
    }

    pub fn verify_opaque(&mut self, signature: &mut Data, plain: &mut Data)
        -> Result<ops::VerifyResult> {
        self.verify(signature, None, Some(plain))
    }

    /// Encrypts a message for the specified recipients.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use gpgme::{self, Data, ops};
    ///
    /// let mut ctx = gpgme::create_context().unwrap();
    /// let key = ctx.find_key("some pattern").unwrap();
    /// let (mut plain, mut cipher) = (Data::new().unwrap(), Data::new().unwrap());
    /// ctx.encrypt(Some(&key), ops::EncryptFlags::empty(), &mut plain, &mut cipher).unwrap();
    /// ```
    pub fn encrypt<'k, I>(&mut self, recp: I, flags: ops::EncryptFlags, plaintext: &mut Data,
        ciphertext: &mut Data)
        -> Result<ops::EncryptResult>
    where I: IntoIterator<Item = &'k Key> {
        let mut ptrs: Vec<_> = recp.into_iter().map(|k| k.as_raw()).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            return_err!(ffi::gpgme_op_encrypt(self.raw,
                                              keys,
                                              flags.bits(),
                                              plaintext.as_raw(),
                                              ciphertext.as_raw()));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn encrypt_symmetric(&mut self, flags: ops::EncryptFlags, plaintext: &mut Data,
        ciphertext: &mut Data)
        -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_op_encrypt(self.raw,
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
    /// use gpgme::{self, Data, ops};
    ///
    /// let mut ctx = gpgme::create_context().unwrap();
    /// let key = ctx.find_key("some pattern").unwrap();
    /// let (mut plain, mut cipher) = (Data::new().unwrap(), Data::new().unwrap());
    /// ctx.encrypt_and_sign(Some(&key), ops::EncryptFlags::empty(),
    ///                      &mut plain, &mut cipher).unwrap();
    /// ```
    pub fn encrypt_and_sign<'k, I>(&mut self, recp: I, flags: ops::EncryptFlags,
        plaintext: &mut Data, ciphertext: &mut Data)
        -> Result<(ops::EncryptResult, ops::SignResult)>
    where I: IntoIterator<Item = &'k Key> {
        let mut ptrs: Vec<_> = recp.into_iter().map(|k| k.as_raw()).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            return_err!(ffi::gpgme_op_encrypt_sign(self.raw,
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
    /// use std::fs::File;
    /// use gpgme::{self, Data, ops};
    ///
    /// let mut ctx = gpgme::create_context().unwrap();
    /// let mut cipher = Data::load("some file").unwrap();
    /// let mut plain = Data::new().unwrap();
    /// ctx.decrypt(&mut cipher, &mut plain).unwrap();
    /// ```
    pub fn decrypt(&mut self, ciphertext: &mut Data, plaintext: &mut Data)
        -> Result<ops::DecryptResult> {
        unsafe {
            return_err!(ffi::gpgme_op_decrypt(self.raw, ciphertext.as_raw(), plaintext.as_raw()));
        }
        Ok(self.get_result().unwrap())
    }

    /// Decrypts and verifies a message.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use gpgme::{self, Data, ops};
    ///
    /// let mut ctx = gpgme::create_context().unwrap();
    /// let mut cipher = Data::load("some file").unwrap();
    /// let mut plain = Data::new().unwrap();
    /// ctx.decrypt_and_verify(&mut cipher, &mut plain).unwrap();
    /// ```
    pub fn decrypt_and_verify(&mut self, ciphertext: &mut Data, plaintext: &mut Data)
        -> Result<(ops::DecryptResult, ops::VerifyResult)> {
        unsafe {
            return_err!(ffi::gpgme_op_decrypt_verify(self.raw,
                                                     ciphertext.as_raw(),
                                                     plaintext.as_raw()))
        }
        Ok((self.get_result().unwrap(), self.get_result().unwrap()))
    }

    fn get_result<R: ops::OpResult>(&self) -> Option<R> {
        R::from_context(self)
    }
}

unsafe impl Wrapper for Context {
    type Raw = ffi::gpgme_ctx_t;

    unsafe fn from_raw(raw: ffi::gpgme_ctx_t) -> Context {
        debug_assert!(!raw.is_null());
        Context { raw: raw }
    }

    fn as_raw(&self) -> ffi::gpgme_ctx_t {
        self.raw
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { ffi::gpgme_release(self.raw) }
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Context").field("raw", &self.raw).finish()
    }
}

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
                                                        secret_only as libc::c_int,
                                                        0));
        }
        Ok(Keys { ctx: ctx })
    }

    pub fn finish(self) -> Result<ops::KeyListResult> {
        let ctx = self.ctx as *mut Context;
        mem::forget(self);
        unsafe {
            return_err!(ffi::gpgme_op_keylist_end((*ctx).as_raw()));
            Ok((*ctx).get_result().unwrap())
        }
    }
}

impl<'a> Drop for Keys<'a> {
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_op_keylist_end(self.ctx.as_raw());
        }
    }
}

impl<'a> Iterator for Keys<'a> {
    type Item = Result<Key>;

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

pub struct TrustItems<'a> {
    ctx: &'a mut Context,
}

impl<'a> TrustItems<'a> {
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
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_op_trustlist_end(self.ctx.as_raw());
        }
    }
}

impl<'a> Iterator for TrustItems<'a> {
    type Item = Result<TrustItem>;

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

#[derive(Debug, Copy, Clone)]
pub struct SignersIter<'a> {
    ctx: &'a Context,
    current: Option<libc::c_int>,
}

impl<'a> Iterator for SignersIter<'a> {
    type Item = Key;

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

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.current = self.current
            .and_then(|x| if (n as i64) <= (libc::c_int::max_value() as i64) {
                x.checked_add(n as libc::c_int)
            } else {
                None
            });
        self.next()
    }
}

#[derive(Debug, Copy, Clone)]
pub struct PassphraseRequest<'a> {
    uid_hint: Option<&'a CStr>,
    context: Option<&'a CStr>,
    pub prev_attempt_failed: bool,
}

impl<'a> PassphraseRequest<'a> {
    pub fn uid_hint(&self) -> result::Result<&'a str, Option<Utf8Error>> {
        self.uid_hint.map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn uid_hint_raw(&self) -> Option<&'a CStr> {
        self.uid_hint
    }

    pub fn context(&self) -> result::Result<&'a str, Option<Utf8Error>> {
        self.context.map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn context_raw(&self) -> Option<&'a CStr> {
        self.context
    }
}

pub trait PassphraseHandler: Send {
    fn handle<W: io::Write>(&mut self, request: PassphraseRequest, out: W) -> Result<()>;
}

impl<T: Send> PassphraseHandler for T
where T: FnMut(PassphraseRequest, &mut io::Write) -> Result<()> {
    fn handle<W: io::Write>(&mut self, request: PassphraseRequest, mut out: W) -> Result<()> {
        (*self)(request, &mut out)
    }
}

struct PassphraseHandlerGuard {
    ctx: ffi::gpgme_ctx_t,
    old: (ffi::gpgme_passphrase_cb_t, *mut libc::c_void),
}

impl Drop for PassphraseHandlerGuard {
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_set_passphrase_cb(self.ctx, self.old.0, self.old.1);
        }
    }
}

extern "C" fn passphrase_callback<H: PassphraseHandler>(hook: *mut libc::c_void,
    uid_hint: *const libc::c_char,
    info: *const libc::c_char,
    was_bad: libc::c_int, fd: libc::c_int)
    -> ffi::gpgme_error_t {
    use std::io::prelude::*;

    let handler = hook as *mut H;
    unsafe {
        let info = PassphraseRequest {
            uid_hint: uid_hint.as_ref().map(|s| CStr::from_ptr(s)),
            context: info.as_ref().map(|s| CStr::from_ptr(s)),
            prev_attempt_failed: was_bad != 0,
        };
        let mut writer = FdWriter::new(fd);
        (*handler)
            .handle(info, &mut writer)
            .and_then(|_| writer.write_all(b"\n").map_err(Error::from))
            .err()
            .map_or(0, |err| err.raw())
    }
}

pub struct ProgressInfo<'a> {
    what: Option<&'a CStr>,
    pub typ: i64,
    pub current: i64,
    pub total: i64,
}

impl<'a> ProgressInfo<'a> {
    pub fn what(&self) -> result::Result<&'a str, Option<Utf8Error>> {
        self.what.map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn what_raw(&self) -> Option<&'a CStr> {
        self.what
    }
}

pub trait ProgressHandler: 'static + Send {
    fn handle(&mut self, info: ProgressInfo);
}

impl<T: 'static + Send> ProgressHandler for T
    where T: FnMut(ProgressInfo) {
    fn handle(&mut self, info: ProgressInfo) {
        (*self)(info);
    }
}

pub struct ProgressHandlerGuard {
    ctx: ffi::gpgme_ctx_t,
    old: (ffi::gpgme_progress_cb_t, *mut libc::c_void),
}

impl Drop for ProgressHandlerGuard {
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_set_progress_cb(self.ctx, self.old.0, self.old.1);
        }
    }
}

extern "C" fn progress_callback<H: ProgressHandler>(hook: *mut libc::c_void,
    what: *const libc::c_char, typ: libc::c_int,
    current: libc::c_int, total: libc::c_int) {
    let handler = hook as *mut H;
    unsafe {
        let info = ProgressInfo {
            what: what.as_ref().map(|s| CStr::from_ptr(s)),
            typ: typ.into(),
            current: current.into(),
            total: total.into(),
        };
        (*handler).handle(info);
    }
}

pub trait StatusHandler: 'static + Send {
    fn handle(&mut self, keyword: Option<&CStr>, args: Option<&CStr>) -> Result<()>;
}

impl<T: 'static + Send> StatusHandler for T
where T: FnMut(Option<&CStr>, Option<&CStr>) -> Result<()> {
    fn handle(&mut self, keyword: Option<&CStr>, args: Option<&CStr>) -> Result<()> {
        (*self)(keyword, args)
    }
}

pub struct StatusHandlerGuard {
    ctx: ffi::gpgme_ctx_t,
    old: (ffi::gpgme_status_cb_t, *mut libc::c_void),
}

impl Drop for StatusHandlerGuard {
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_set_status_cb(self.ctx, self.old.0, self.old.1);
        }
    }
}

extern "C" fn status_callback<H: StatusHandler>(hook: *mut libc::c_void,
    keyword: *const libc::c_char,
    args: *const libc::c_char)
    -> ffi::gpgme_error_t {
    let handler = hook as *mut H;
    unsafe {
        let keyword = keyword.as_ref().map(|s| CStr::from_ptr(s));
        let args = args.as_ref().map(|s| CStr::from_ptr(s));
        (*handler).handle(args, keyword).err().map(|err| err.raw()).unwrap_or(0)
    }
}

pub struct EditStatus<'a> {
    pub code: edit::StatusCode,
    args: Option<&'a CStr>,
    pub response: &'a mut Data<'a>,
}

impl<'a> EditStatus<'a> {
    pub fn args(&self) -> result::Result<&'a str, Option<Utf8Error>> {
        match self.args {
            Some(s) => s.to_str().map_err(Some),
            None => Err(None),
        }
    }

    pub fn args_raw(&self) -> Option<&'a CStr> {
        self.args
    }
}

pub trait EditHandler: 'static + Send {
    fn handle<W: io::Write>(&mut self, status: EditStatus, out: Option<W>) -> Result<()>;
}

struct EditHandlerWrapper<'a, E: EditHandler> {
    handler: E,
    response: *mut Data<'a>,
}

extern "C" fn edit_callback<E: EditHandler>(hook: *mut libc::c_void,
    status: ffi::gpgme_status_code_t,
    args: *const libc::c_char, fd: libc::c_int)
    -> ffi::gpgme_error_t {
    let wrapper = hook as *mut EditHandlerWrapper<E>;
    let result = unsafe {
        let status = EditStatus {
            code: edit::StatusCode::from_raw(status),
            args: args.as_ref().map(|s| CStr::from_ptr(s)),
            response: &mut *(*wrapper).response,
        };
        if fd < 0 {
            (*wrapper).handler.handle(status, None::<&mut io::Write>)
        } else {
            (*wrapper).handler.handle(status, Some(FdWriter::new(fd)))
        }
    };
    result.err().map(|err| err.raw()).unwrap_or(0)
}

pub struct InteractStatus<'a> {
    keyword: Option<&'a CStr>,
    args: Option<&'a CStr>,
    pub response: &'a mut Data<'a>,
}

impl<'a> InteractStatus<'a> {
    pub fn keyword(&self) -> result::Result<&'a str, Option<Utf8Error>> {
        self.keyword.map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn keyword_raw(&self) -> Option<&'a CStr> {
        self.keyword
    }

    pub fn args(&self) -> result::Result<&'a str, Option<Utf8Error>> {
        self.args.map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn args_raw(&self) -> Option<&'a CStr> {
        self.args
    }
}

pub trait InteractHandler: 'static + Send {
    fn handle<W: io::Write>(&mut self, status: InteractStatus, out: Option<W>) -> Result<()>;
}

struct InteractHandlerWrapper<'a, H: InteractHandler> {
    handler: H,
    response: *mut Data<'a>,
}

extern "C" fn interact_callback<H: InteractHandler>(hook: *mut libc::c_void,
    keyword: *const libc::c_char,
    args: *const libc::c_char, fd: libc::c_int)
    -> ffi::gpgme_error_t {
    let wrapper = hook as *mut InteractHandlerWrapper<H>;
    let result = unsafe {
        let status = InteractStatus {
            keyword: keyword.as_ref().map(|s| CStr::from_ptr(s)),
            args: args.as_ref().map(|s| CStr::from_ptr(s)),
            response: &mut *(*wrapper).response,
        };
        if fd < 0 {
            (*wrapper).handler.handle(status, None::<&mut io::Write>)
        } else {
            (*wrapper).handler.handle(status, Some(FdWriter::new(fd)))
        }
    };
    result.err().map(|err| err.raw()).unwrap_or(0)
}
