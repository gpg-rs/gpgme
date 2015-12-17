use std::ffi::CString;
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::ptr;

use libc;
use ffi;

use {Protocol, Token, Wrapper};
use error::{self, Error, Result};
use engine::{EngineInfo, EngineInfoIter};
use data::Data;
use keys::Key;
use trust::TrustItem;
use notation::{self, SignatureNotationIter};
use utils::{self, FdWriter};
use ops;

/// A context for cryptographic operations
pub struct Context {
    raw: ffi::gpgme_ctx_t,
}

impl Context {
    pub fn new(_: Token) -> Result<Self> {
        let mut ctx = ptr::null_mut();
        unsafe {
            return_err!(ffi::gpgme_new(&mut ctx));
            Ok(Context::from_raw(ctx))
        }
    }

    pub fn has_armor(&self) -> bool {
        unsafe { ffi::gpgme_get_armor(self.raw) == 1 }
    }

    pub fn set_armor(&mut self, enabled: bool) {
        unsafe {
            ffi::gpgme_set_armor(self.raw, enabled as libc::c_int);
        }
    }

    pub fn text_mode(&self) -> bool {
        unsafe { ffi::gpgme_get_textmode(self.raw) == 1 }
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

    /// Sets the passphrase callback for the context and returns a guard for the context.
    ///
    /// When the guard is dropped the context's passphrase callback will be reset to its
    /// previous value.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io::prelude::*;
    ///
    /// let mut ctx = gpgme::create_context().unwrap();
    /// let cb = &mut |_: Option<&str>, _: Option<&str>, _, out: &mut Write| {
    ///     try!(out.write_all(b"some passphrase"));
    ///     Ok(())
    /// };
    /// let mut guard = ctx.with_passphrase_cb(cb);
    /// // Do something with guard requiring a passphrase e.g. decryption
    /// ```
    pub fn with_passphrase_cb<'s, 'a, C>(&'s mut self, cb: &'a mut C)
        -> PassphraseCallbackGuard<'s, 'a>
    where C: PassphraseCallback {
        unsafe {
            let mut old = (None, ptr::null_mut());
            ffi::gpgme_get_passphrase_cb(self.raw, &mut old.0, &mut old.1);
            ffi::gpgme_set_passphrase_cb(self.raw,
                                         Some(passphrase_callback::<C>),
                                         (cb as *mut _) as *mut _);
            PassphraseCallbackGuard {
                ctx: self,
                old: old,
                _cb: PhantomData,
            }
        }
    }

    pub fn with_progress_cb<'s, 'a, C>(&'s mut self, cb: &'a mut C) -> ProgressCallbackGuard<'s, 'a>
    where C: ProgressCallback {
        unsafe {
            let mut old = (None, ptr::null_mut());
            ffi::gpgme_get_progress_cb(self.raw, &mut old.0, &mut old.1);
            ffi::gpgme_set_progress_cb(self.raw,
                                       Some(progress_callback::<C>),
                                       (cb as *mut _) as *mut _);
            ProgressCallbackGuard {
                ctx: self,
                old: old,
                _cb: PhantomData,
            }
        }
    }

    pub fn engine_info(&self) -> EngineInfoIter<Context> {
        unsafe { EngineInfoIter::from_list(ffi::gpgme_ctx_get_engine_info(self.raw)) }
    }

    pub fn get_engine_info(&self, proto: Protocol) -> Option<EngineInfo<Context>> {
        self.engine_info().find(|info| info.protocol() == proto)
    }

    pub fn set_engine_info(&mut self, proto: Protocol, filename: Option<String>,
        home_dir: Option<String>)
        -> Result<()> {
        let filename = try!(filename.map_or(Ok(None), |s| CString::new(s).map(Some)));
        let home_dir = try!(home_dir.map_or(Ok(None), |s| CString::new(s).map(Some)));
        unsafe {
            let filename = filename.map_or(ptr::null(), |s| s.as_ptr());
            let home_dir = home_dir.map_or(ptr::null(), |s| s.as_ptr());
            return_err!(ffi::gpgme_ctx_set_engine_info(self.raw, proto.raw(), filename, home_dir));
        }
        Ok(())
    }

    pub fn find_trust_items<S: Into<String>>(&mut self, pattern: S, max_level: i32)
        -> Result<TrustItems> {
        let pattern = try!(CString::new(pattern.into()));
        unsafe {
            return_err!(ffi::gpgme_op_trustlist_start(self.raw,
                                                      pattern.as_ptr(),
                                                      max_level.into()));
        }
        Ok(TrustItems { ctx: self })
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
    pub fn find_key<S: Into<String>>(&self, fingerprint: S) -> Result<Key> {
        let fingerprint = try!(CString::new(fingerprint.into()));
        unsafe {
            let mut key = ptr::null_mut();
            return_err!(ffi::gpgme_get_key(self.raw, fingerprint.as_ptr(), &mut key, 0));
            Ok(Key::from_raw(key))
        }
    }

    /// Returns the secret key with the specified fingerprint, if such a key can
    /// be found. Otherwise, an error is returned.
    pub fn find_secret_key<S: Into<String>>(&self, fingerprint: S) -> Result<Key> {
        let fingerprint = try!(CString::new(fingerprint.into()));
        unsafe {
            let mut key = ptr::null_mut();
            return_err!(ffi::gpgme_get_key(self.raw, fingerprint.as_ptr(), &mut key, 1));
            Ok(Key::from_raw(key))
        }
    }

    /// Returns an iterator for a list of all public keys matching one or more of the
    /// specified patterns.
    pub fn find_keys<I>(&mut self, patterns: I) -> Result<Keys>
    where I: IntoIterator, I::Item: Into<String> {
        Keys::new(self, patterns, false)
    }

    /// Returns an iterator for a list of all secret keys matching one or more of the
    /// specified patterns.
    pub fn find_secret_keys<I>(&mut self, patterns: I) -> Result<Keys>
    where I: IntoIterator, I::Item: Into<String> {
        Keys::new(self, patterns, true)
    }

    pub fn generate_key<S: Into<String>>(&mut self, params: S, public: Option<&mut Data>,
        secret: Option<&mut Data>)
        -> Result<ops::KeyGenerateResult> {
        let params = try!(CString::new(params.into()));
        let public = public.map_or(ptr::null_mut(), |d| d.as_raw());
        let secret = secret.map_or(ptr::null_mut(), |d| d.as_raw());
        unsafe {
            return_err!(ffi::gpgme_op_genkey(self.raw, params.as_ptr(), public, secret));
        }
        Ok(self.get_result().unwrap())
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
    where I: IntoIterator, I::Item: Into<String> {
        let mut strings = Vec::new();
        for pattern in patterns {
            strings.push(try!(CString::new(pattern.into())));
        }
        let data = data.map_or(ptr::null_mut(), |d| d.as_raw());
        match strings.len() {
            0 | 1 => unsafe {
                let pattern = strings.first().map_or(ptr::null(), |s| s.as_ptr());
                return_err!(ffi::gpgme_op_export(self.raw, pattern, mode.bits(), data));
            },
            _ => unsafe {
                let mut ptrs: Vec<_> = strings.iter().map(|s| s.as_ptr()).collect();
                ptrs.push(ptr::null());
                return_err!(ffi::gpgme_op_export_ext(self.raw,
                                                     ptrs.as_mut_ptr(),
                                                     mode.bits(),
                                                     data));
            },
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

    // Only works with GPG >= 2.0.15
    pub fn change_key_passphrase(&mut self, key: &Key) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_op_passwd(self.raw, key.as_raw(), 0));
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

    pub fn add_notation<S1, S2>(&mut self, name: S1, value: S2, flags: notation::Flags) -> Result<()>
    where S1: Into<String>, S2: Into<String> {
        let name = try!(CString::new(name.into()));
        let value = try!(CString::new(value.into()));
        unsafe {
            return_err!(ffi::gpgme_sig_notation_add(self.raw,
                                                    name.as_ptr(),
                                                    value.as_ptr(),
                                                    flags.bits()));
        }
        Ok(())
    }

    pub fn add_policy_url<S: Into<String>>(&mut self, url: S, critical: bool) -> Result<()> {
        let url = try!(CString::new(url.into()));
        unsafe {
            let critical = if critical {
                ffi::GPGME_SIG_NOTATION_CRITICAL
            } else {
                0
            };
            return_err!(ffi::gpgme_sig_notation_add(self.raw, ptr::null(), url.as_ptr(), critical));
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
    pub fn encrypt<'k, I>(&mut self, recp: I, flags: ops::EncryptFlags, plain: &mut Data,
        cipher: &mut Data)
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
                                              plain.as_raw(),
                                              cipher.as_raw()));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn encrypt_symmetric(&mut self, flags: ops::EncryptFlags, plain: &mut Data,
        cipher: &mut Data)
        -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_op_encrypt(self.raw,
                                              ptr::null_mut(),
                                              flags.bits(),
                                              plain.as_raw(),
                                              cipher.as_raw()));
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
    pub fn encrypt_and_sign<'k, I>(&mut self, recp: I, flags: ops::EncryptFlags, plain: &mut Data,
        cipher: &mut Data)
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
                                                   plain.as_raw(),
                                                   cipher.as_raw()))
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
    /// let mut cipher = Data::load(&"some file").unwrap();
    /// let mut plain = Data::new().unwrap();
    /// ctx.decrypt(&mut cipher, &mut plain).unwrap();
    /// ```
    pub fn decrypt(&mut self, cipher: &mut Data, plain: &mut Data) -> Result<ops::DecryptResult> {
        unsafe {
            return_err!(ffi::gpgme_op_decrypt(self.raw, cipher.as_raw(), plain.as_raw()));
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
    /// let mut cipher = Data::load(&"some file").unwrap();
    /// let mut plain = Data::new().unwrap();
    /// ctx.decrypt_and_verify(&mut cipher, &mut plain).unwrap();
    /// ```
    pub fn decrypt_and_verify(&mut self, cipher: &mut Data, plain: &mut Data)
        -> Result<(ops::DecryptResult, ops::VerifyResult)> {
        unsafe {
            return_err!(ffi::gpgme_op_decrypt_verify(self.raw, cipher.as_raw(), plain.as_raw()))
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
    fn new<'b, I>(ctx: &'b mut Context, patterns: I, secret_only: bool) -> Result<Keys<'b>>
    where I: IntoIterator, I::Item: Into<String> {
        let mut strings = Vec::new();
        for pattern in patterns {
            strings.push(try!(CString::new(pattern.into())));
        }
        match strings.len() {
            0 | 1 => unsafe {
                let pattern = strings.first().map_or(ptr::null(), |s| s.as_ptr());
                return_err!(ffi::gpgme_op_keylist_start(ctx.as_raw(),
                                                        pattern,
                                                        secret_only as libc::c_int));
            },
            _ => unsafe {
                let mut ptrs: Vec<_> = strings.iter().map(|s| s.as_ptr()).collect();
                ptrs.push(ptr::null());
                return_err!(ffi::gpgme_op_keylist_ext_start(ctx.as_raw(),
                                                            ptrs.as_mut_ptr(),
                                                            secret_only as libc::c_int,
                                                            0));
            },
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
        let mut key: ffi::gpgme_key_t = ptr::null_mut();
        unsafe {
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
            self.current.and_then(|x| {
                let key = ffi::gpgme_signers_enum(self.ctx.as_raw(), x);
                if !key.is_null() {
                    self.current = x.checked_add(1);
                    Some(Key::from_raw(key))
                } else {
                    self.current = None;
                    None
                }
            })
        }
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.current = self.current.and_then(|x| {
            if (n as i64) <= (libc::c_int::max_value() as i64) {
                x.checked_add(n as libc::c_int)
            } else {
                None
            }
        });
        self.next()
    }
}

pub trait PassphraseCallback: 'static + Send {
    fn call(&mut self, uid_hint: Option<&str>, info: Option<&str>, prev_was_bad: bool,
        out: &mut io::Write)
        -> Result<()>;
}

impl<T: 'static + Send> PassphraseCallback for T
where T: FnMut(Option<&str>, Option<&str>, bool, &mut io::Write) -> Result<()> {
    fn call(&mut self, uid_hint: Option<&str>, info: Option<&str>, prev_was_bad: bool,
        out: &mut io::Write)
        -> Result<()> {
        (*self)(uid_hint, info, prev_was_bad, out)
    }
}

pub struct PassphraseCallbackGuard<'a, 'b> {
    _cb: PhantomData<&'b mut PassphraseCallback>,
    ctx: &'a mut Context,
    old: (ffi::gpgme_passphrase_cb_t, *mut libc::c_void),
}

impl<'a, 'b> Drop for PassphraseCallbackGuard<'a, 'b> {
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_set_passphrase_cb(self.ctx.as_raw(), self.old.0, self.old.1);
        }
    }
}

impl<'a, 'b> Deref for PassphraseCallbackGuard<'a, 'b> {
    type Target = Context;

    fn deref(&self) -> &Context {
        self.ctx
    }
}

impl<'a, 'b> DerefMut for PassphraseCallbackGuard<'a, 'b> {
    fn deref_mut(&mut self) -> &mut Context {
        self.ctx
    }
}

pub trait ProgressCallback: 'static + Send {
    fn call(&mut self, what: Option<&str>, typ: isize, current: isize, total: isize);
}

impl<T: 'static + Send> ProgressCallback for T where T: FnMut(Option<&str>, isize, isize, isize) {
    fn call(&mut self, what: Option<&str>, typ: isize, current: isize, total: isize) {
        (*self)(what, typ, current, total);
    }
}

pub struct ProgressCallbackGuard<'a, 'b> {
    _cb: PhantomData<&'b mut ProgressCallback>,
    ctx: &'a mut Context,
    old: (ffi::gpgme_progress_cb_t, *mut libc::c_void),
}

impl<'a, 'b> Drop for ProgressCallbackGuard<'a, 'b> {
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_set_progress_cb(self.ctx.as_raw(), self.old.0, self.old.1);
        }
    }
}

impl<'a, 'b> Deref for ProgressCallbackGuard<'a, 'b> {
    type Target = Context;

    fn deref(&self) -> &Context {
        self.ctx
    }
}

impl<'a, 'b> DerefMut for ProgressCallbackGuard<'a, 'b> {
    fn deref_mut(&mut self) -> &mut Context {
        self.ctx
    }
}

extern "C" fn passphrase_callback<C: PassphraseCallback>(hook: *mut libc::c_void,
    uid_hint: *const libc::c_char,
    info: *const libc::c_char,
    was_bad: libc::c_int, fd: libc::c_int)
    -> ffi::gpgme_error_t {
    use std::io::prelude::*;

    let cb = hook as *mut C;
    unsafe {
        let uid_hint = utils::from_cstr(uid_hint);
        let info = utils::from_cstr(info);
        let mut writer = FdWriter::new(fd);
        (*cb)
            .call(uid_hint, info, was_bad != 0, &mut writer)
            .and_then(|_| writer.write_all(b"\n").map_err(Error::from))
            .err()
            .map_or(0, |err| err.raw())
    }
}

extern "C" fn progress_callback<C: ProgressCallback>(hook: *mut libc::c_void,
    what: *const libc::c_char, typ: libc::c_int,
    current: libc::c_int, total: libc::c_int) {
    let cb = hook as *mut C;
    unsafe {
        let what = utils::from_cstr(what);
        (*cb).call(what, typ as isize, current as isize, total as isize);
    }
}
