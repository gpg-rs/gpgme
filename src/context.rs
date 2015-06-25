use std::ffi::CString;
use std::fmt;
use std::io;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::ptr;

use libc;

use enum_primitive::FromPrimitive;

use gpgme_sys as sys;

use {Protocol, Token};
use error::{Result, Error};
use engine::{EngineInfo, EngineInfoIter};
use data::Data;
use keys::Key;
use notation::{SignatureNotationFlags, SignatureNotationIter};
use utils::{self, FdWriter};
use ops;

pub trait PassphraseCallback: 'static + Send {
    fn read(&mut self, uid_hint: Option<&str>, info: Option<&str>,
            prev_was_bad: bool, out: &mut io::Write) -> Result<()>;
}

impl<T: 'static + Send> PassphraseCallback for T
        where T: FnMut(Option<&str>, Option<&str>, bool, &mut io::Write) -> Result<()> {
    fn read(&mut self, uid_hint: Option<&str>, info: Option<&str>,
            prev_was_bad: bool, out: &mut io::Write) -> Result<()> {
        (*self)(uid_hint, info, prev_was_bad, out)
    }
}

pub trait ProgressCallback: 'static + Send {
    fn report(&mut self, what: Option<&str>, typ: isize, current: isize, total: isize);
}

impl<T: 'static + Send> ProgressCallback for T where T: FnMut(Option<&str>, isize, isize, isize) {
    fn report(&mut self, what: Option<&str>, typ: isize, current: isize, total: isize) {
        (*self)(what, typ, current, total);
    }
}

/// A context for cryptographic operations
pub struct Context {
    raw: sys::gpgme_ctx_t,
    lib: Token,
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            sys::gpgme_release(self.raw)
        }
    }
}

impl Context {
    pub unsafe fn from_raw(ctx: sys::gpgme_ctx_t, lib: Token) -> Context {
        Context { raw: ctx, lib: lib }
    }

    pub fn as_raw(&self) -> sys::gpgme_ctx_t {
        self.raw
    }

    pub fn new(lib: Token) -> Result<Context> {
        let mut ctx: sys::gpgme_ctx_t = ptr::null_mut();
        unsafe {
            return_err!(sys::gpgme_new(&mut ctx));
        }
        Ok(Context { raw: ctx, lib: lib })
    }

    pub fn token(&self) -> &Token {
        &self.lib
    }

    pub fn has_armor(&self) -> bool {
        unsafe {
            sys::gpgme_get_armor(self.raw) == 1
        }
    }

    pub fn set_armor(&mut self, enabled: bool) {
        unsafe {
            sys::gpgme_set_armor(self.raw, enabled as libc::c_int);
        }
    }

    pub fn text_mode(&self) -> bool {
        unsafe {
            sys::gpgme_get_textmode(self.raw) == 1
        }
    }

    pub fn set_text_mode(&mut self, enabled: bool) {
        unsafe {
            sys::gpgme_set_textmode(self.raw, enabled as libc::c_int);
        }
    }

    pub fn protocol(&self) -> Protocol {
        unsafe {
            Protocol::from_u64(sys::gpgme_get_protocol(self.raw) as u64)
                .unwrap_or(Protocol::Unknown)
        }
    }

    pub fn set_protocol(&mut self, proto: Protocol) -> Result<()> {
        unsafe {
            return_err!(sys::gpgme_set_protocol(self.raw, proto as sys::gpgme_protocol_t));
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
    /// let mut guard = ctx.with_passphrase_cb(|_: Option<&str>, _: Option<&str>, _, out: &mut Write| {
    ///     try!(out.write_all(b"\n"));
    ///     Ok(())
    /// });
    /// // Do something with guard requiring a passphrase e.g. decryption
    /// ```
    pub fn with_passphrase_cb<C: PassphraseCallback>(&mut self, cb: C)
        -> PassphraseCallbackGuard<C> {
        let cb = Box::new(cb);
        unsafe {
            let mut old = (None, ptr::null_mut());
            sys::gpgme_get_passphrase_cb(self.raw, &mut old.0, &mut old.1);
            sys::gpgme_set_passphrase_cb(self.raw, Some(passphrase_callback::<C>),
                                         mem::transmute(&*cb));
            PassphraseCallbackGuard {
                ctx: self,
                old: old,
                _cb: cb,
            }
        }
    }

    pub fn with_progress_cb<C: ProgressCallback>(&mut self, cb: C)
        -> ProgressCallbackGuard<C> {
        let cb = Box::new(cb);
        unsafe {
            let mut old = (None, ptr::null_mut());
            sys::gpgme_get_progress_cb(self.raw, &mut old.0, &mut old.1);
            sys::gpgme_set_progress_cb(self.raw, Some(progress_callback::<C>),
                                         mem::transmute(&*cb));
            ProgressCallbackGuard {
                ctx: self,
                old: old,
                _cb: cb,
            }
        }
    }

    pub fn engine_info(&self) -> EngineInfoIter<Context> {
        unsafe {
            EngineInfoIter::from_list(sys::gpgme_ctx_get_engine_info(self.raw))
        }
    }

    pub fn get_engine_info(&self, proto: Protocol) -> Option<EngineInfo<Context>> {
        self.engine_info().find(|info| info.protocol() == proto)
    }

    pub fn set_engine_info(&mut self, proto: Protocol, filename: Option<String>,
                           home_dir: Option<String>) -> Result<()> {
        let filename = try!(filename.map_or(Ok(None), |s| CString::new(s).map(Some)));
        let home_dir = try!(home_dir.map_or(Ok(None), |s| CString::new(s).map(Some)));
        unsafe {
            let filename = filename.map_or(ptr::null(), |s| s.as_ptr());
            let home_dir = home_dir.map_or(ptr::null(), |s| s.as_ptr());
            return_err!(sys::gpgme_ctx_set_engine_info(self.raw, proto as sys::gpgme_protocol_t,
                                                      filename, home_dir));
        }
        Ok(())
    }

    pub fn key_list_mode(&self) -> ops::KeyListMode {
        unsafe {
            ops::KeyListMode::from_bits_truncate(sys::gpgme_get_keylist_mode(self.raw))
        }
    }

    pub fn set_key_list_mode(&mut self, mask: ops::KeyListMode) -> Result<()> {
        unsafe {
            let old = sys::gpgme_get_keylist_mode(self.raw);
            return_err!(sys::gpgme_set_keylist_mode(self.raw, mask.bits() |
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

    pub fn find_key<S: Into<String>>(&self, pattern: S) -> Result<Key> {
        let mut key: sys::gpgme_key_t = ptr::null_mut();
        let pattern = try!(CString::new(pattern.into()));
        unsafe {
            return_err!(sys::gpgme_get_key(self.raw, pattern.as_ptr(),
                &mut key, false as libc::c_int));
            Ok(Key::from_raw(key))
        }
    }

    pub fn find_secret_key<S: Into<String>>(&self, pattern: S) -> Result<Key> {
        let mut key: sys::gpgme_key_t = ptr::null_mut();
        let pattern = try!(CString::new(pattern.into()));
        unsafe {
            return_err!(sys::gpgme_get_key(self.raw, pattern.as_ptr(),
                &mut key, true as libc::c_int));
            Ok(Key::from_raw(key))
        }
    }

    pub fn find_keys<I>(&mut self, patterns: I) -> Result<Keys>
            where I: IntoIterator, I::Item: Into<String> {
        Keys::new(self, patterns, false)
    }

    pub fn find_secret_keys<I>(&mut self, patterns: I) -> Result<Keys>
            where I: IntoIterator, I::Item: Into<String> {
        Keys::new(self, patterns, true)
    }

    pub fn key_list_result(&self) -> Option<ops::KeyListResult> {
        self.get_result()
    }

    pub fn generate_key<S: Into<String>>(&mut self, params: S, public: Option<&mut Data>,
                        secret: Option<&mut Data>) -> Result<ops::KeyGenerateResult> {
        let params = try!(CString::new(params.into()));
        let public = public.map(|d| d.as_raw()).unwrap_or(ptr::null_mut());
        let secret = secret.map(|d| d.as_raw()).unwrap_or(ptr::null_mut());
        unsafe {
            return_err!(sys::gpgme_op_genkey(self.raw, params.as_ptr(), public, secret));
        }
        Ok(self.generate_key_result().unwrap())
    }

    pub fn generate_key_result(&self) -> Option<ops::KeyGenerateResult> {
        self.get_result()
    }

    pub fn import(&mut self, key_data: &mut Data) -> Result<ops::ImportResult> {
        unsafe {
            return_err!(sys::gpgme_op_import(self.raw, key_data.as_raw()));
        }
        Ok(self.import_result().unwrap())
    }

    pub fn import_keys<'k, I>(&mut self, keys: I) -> Result<ops::ImportResult>
            where I: IntoIterator<Item=&'k Key> {
        let mut ptrs: Vec<_> = keys.into_iter().map(|k| k.as_raw()).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            return_err!(sys::gpgme_op_import_keys(self.raw, keys));
        }
        Ok(self.import_result().unwrap())
    }

    pub fn import_result(&self) -> Option<ops::ImportResult> {
        self.get_result()
    }

    pub fn export_all(&mut self, mode: ops::ExportMode, data: Option<&mut Data>) -> Result<()> {
        self.export(None::<String>, mode, data)
    }

    pub fn export<I>(&mut self, patterns: I, mode: ops::ExportMode,
                           data: Option<&mut Data>) -> Result<()>
            where I: IntoIterator, I::Item: Into<String> {
        let mut strings = Vec::new();
        for pattern in patterns.into_iter() {
            strings.push(try!(CString::new(pattern.into())));
        }
        let data = data.map_or(ptr::null_mut(), |d| d.as_raw());
        match strings.len() {
            0 | 1 => unsafe {
                let pattern = strings.first().map_or(ptr::null(), |s| s.as_ptr());
                return_err!(sys::gpgme_op_export(self.raw, pattern, mode.bits(), data));
            },
            _ => unsafe {
                let mut ptrs: Vec<_> = strings.iter().map(|s| s.as_ptr()).collect();
                ptrs.push(ptr::null());
                return_err!(sys::gpgme_op_export_ext(self.raw, ptrs.as_mut_ptr(),
                                                     mode.bits(), data));
            },
        }
        Ok(())
    }

    pub fn export_keys<'k, I>(&mut self, keys: I, mode: ops::ExportMode,
                       data: Option<&mut Data>) -> Result<()>
            where I: IntoIterator<Item=&'k Key> {
        let data = data.map_or(ptr::null_mut(), |d| d.as_raw());
        let mut ptrs: Vec<_> = keys.into_iter().map(|k| k.as_raw()).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            return_err!(sys::gpgme_op_export_keys(self.raw, keys, mode.bits(), data));
        }
        Ok(())
    }

    pub fn delete_key(&mut self, key: &Key) -> Result<()> {
        unsafe {
            return_err!(sys::gpgme_op_delete(self.raw, key.as_raw(), 0));
        }
        Ok(())
    }

    pub fn delete_secret_key(&mut self, key: &Key) -> Result<()> {
        unsafe {
            return_err!(sys::gpgme_op_delete(self.raw, key.as_raw(), 1));
        }
        Ok(())
    }

    pub fn clear_signers(&mut self) {
        unsafe {
            sys::gpgme_signers_clear(self.raw)
        }
    }

    pub fn add_signer(&mut self, key: &Key) -> Result<()> {
        unsafe {
            return_err!(sys::gpgme_signers_add(self.raw, key.as_raw()));
        }
        Ok(())
    }

    pub fn signers_count(&self) -> usize {
        unsafe {
            sys::gpgme_signers_count(self.raw) as usize
        }
    }

    pub fn signers(&self) -> SignersIter {
        SignersIter { ctx: self, current: 0 }
    }

    pub fn clear_notations(&mut self) {
        unsafe {
            sys::gpgme_sig_notation_clear(self.raw);
        }
    }

    pub fn add_notation<S: Into<String>>(&mut self, name: Option<String>, value: S,
                        flags: SignatureNotationFlags) -> Result<()> {
        let name = try!(name.map_or(Ok(None), |s| CString::new(s).map(Some)));
        let value = try!(CString::new(value.into()));
        unsafe {
            let name = name.map_or(ptr::null(), |s| s.as_ptr());
            return_err!(sys::gpgme_sig_notation_add(self.raw, name, value.as_ptr(),
                                                    flags.bits()));
        }
        Ok(())
    }

    pub fn notations(&self) -> SignatureNotationIter<Context> {
        unsafe {
            SignatureNotationIter::from_list(sys::gpgme_sig_notation_get(self.raw))
        }
    }

    pub fn sign(&mut self, mode: ops::SignMode, plain: &mut Data,
                signature: &mut Data) -> Result<ops::SignResult> {
        unsafe {
            return_err!(sys::gpgme_op_sign(self.raw, plain.as_raw(), signature.as_raw(),
                               mode as sys::gpgme_sig_mode_t));
        }
        Ok(self.sign_result().unwrap())
    }

    pub fn sign_result(&self) -> Option<ops::SignResult> {
        self.get_result()
    }

    pub fn verify(&mut self, signature: &mut Data, signed: Option<&mut Data>,
                  plain: Option<&mut Data>) -> Result<ops::VerifyResult> {
        let signed = signed.map_or(ptr::null_mut(), |d| d.as_raw());
        let plain = plain.map_or(ptr::null_mut(), |d| d.as_raw());
        unsafe {
            return_err!(sys::gpgme_op_verify(self.raw, signature.as_raw(), signed, plain));
        }
        Ok(self.verify_result().unwrap())
    }

    pub fn verify_result(&self) -> Option<ops::VerifyResult> {
        self.get_result()
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
    pub fn encrypt<'k, I>(&mut self, recp: I, flags: ops::EncryptFlags,
                   plain: &mut Data, cipher: &mut Data) -> Result<ops::EncryptResult>
            where I: IntoIterator<Item=&'k Key> {
        let mut ptrs: Vec<_> = recp.into_iter().map(|k| k.as_raw()).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            return_err!(sys::gpgme_op_encrypt(self.raw, keys, flags.bits(), plain.as_raw(),
                                              cipher.as_raw()));
        }
        Ok(self.encrypt_result().unwrap())
    }

    pub fn encrypt_result(&self) -> Option<ops::EncryptResult> {
        self.get_result()
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
            return_err!(sys::gpgme_op_decrypt(self.raw, cipher.as_raw(), plain.as_raw()));
        }
        Ok(self.decrypt_result().unwrap())
    }

    pub fn decrypt_result(&self) -> Option<ops::DecryptResult> {
        self.get_result()
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
                            plain: &mut Data, cipher: &mut Data) -> Result<(ops::EncryptResult, ops::SignResult)>
            where I: IntoIterator<Item=&'k Key> {
        let mut ptrs: Vec<_> = recp.into_iter().map(|k| k.as_raw()).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            return_err!(sys::gpgme_op_encrypt_sign(self.raw, keys, flags.bits(), plain.as_raw(),
                                                   cipher.as_raw()))
        }
        Ok((self.encrypt_result().unwrap(), self.sign_result().unwrap()))
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
            return_err!(sys::gpgme_op_decrypt_verify(self.raw, cipher.as_raw(), plain.as_raw()))
        }
        Ok((self.decrypt_result().unwrap(), self.verify_result().unwrap()))
    }

    pub fn get_result<R: ops::Result>(&self) -> Option<R> {
        R::from_context(self)
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Context {{ raw: {:p} }}", self.raw)
    }
}

pub struct Keys<'a> {
    ctx: &'a mut Context,
}

impl<'a> Keys<'a> {
    fn new<'b, I>(ctx: &'b mut Context, patterns: I,
               secret_only: bool) -> Result<Keys<'b>>
            where I: IntoIterator, I::Item: Into<String> {
        let mut strings = Vec::new();
        for pattern in patterns.into_iter() {
            strings.push(try!(CString::new(pattern.into())));
        }
        match strings.len() {
            0 | 1 => unsafe {
                let pattern = strings.first().map_or(ptr::null(), |s| s.as_ptr());
                return_err!(sys::gpgme_op_keylist_start(ctx.as_raw(), pattern,
                                                        secret_only as libc::c_int));
            },
            _ => unsafe {
                let mut ptrs: Vec<_> = strings.iter().map(|s| s.as_ptr()).collect();
                ptrs.push(ptr::null());
                return_err!(sys::gpgme_op_keylist_ext_start(ctx.as_raw(), ptrs.as_mut_ptr(),
                                                            secret_only as libc::c_int, 0));
            },
        }
        Ok(Keys { ctx: ctx })
    }

    pub fn result(self) -> Result<ops::KeyListResult> {
        let ctx = self.ctx as *mut Context;
        mem::forget(self);
        unsafe {
            return_err!(sys::gpgme_op_keylist_end((*ctx).as_raw()));
            Ok((*ctx).key_list_result().unwrap())
        }
    }
}

impl<'a> Drop for Keys<'a> {
    fn drop(&mut self) {
        unsafe {
            sys::gpgme_op_keylist_end(self.ctx.as_raw());
        }
    }
}

impl<'a> Iterator for Keys<'a> {
    type Item = Result<Key>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut key: sys::gpgme_key_t = ptr::null_mut();
        unsafe {
            let result = sys::gpgme_op_keylist_next(self.ctx.as_raw(), &mut key);
            if sys::gpgme_err_code(result) != sys::GPG_ERR_EOF {
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

#[derive(Debug, Copy, Clone)]
pub struct SignersIter<'a> {
    ctx: &'a Context,
    current: usize,
}

impl<'a> Iterator for SignersIter<'a> {
    type Item = Key;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let key = sys::gpgme_signers_enum(self.ctx.as_raw(), self.current as libc::c_int);
            if !key.is_null() {
                self.current += 1;
                Some(Key::from_raw(key))
            } else {
                None
            }
        }
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.current += n;
        self.next()
    }
}

pub struct PassphraseCallbackGuard<'a, C> {
    ctx: &'a mut Context,
    old: (sys::gpgme_passphrase_cb_t, *mut libc::c_void),
    _cb: Box<C>,
}

impl<'a, C> Drop for PassphraseCallbackGuard<'a, C> {
    fn drop(&mut self) {
        unsafe {
            sys::gpgme_set_passphrase_cb(self.ctx.as_raw(), self.old.0, self.old.1);
        }
    }
}

impl<'a, C> Deref for PassphraseCallbackGuard<'a, C> {
    type Target = Context;

    fn deref(&self) -> &Context {
        self.ctx
    }
}

impl<'a, C> DerefMut for PassphraseCallbackGuard<'a, C> {
    fn deref_mut(&mut self) -> &mut Context {
        self.ctx
    }
}

pub struct ProgressCallbackGuard<'a, C> {
    ctx: &'a mut Context,
    old: (sys::gpgme_progress_cb_t, *mut libc::c_void),
    _cb: Box<C>,
}

impl<'a, C> Drop for ProgressCallbackGuard<'a, C> {
    fn drop(&mut self) {
        unsafe {
            sys::gpgme_set_progress_cb(self.ctx.as_raw(), self.old.0, self.old.1);
        }
    }
}

impl<'a, C> Deref for ProgressCallbackGuard<'a, C> {
    type Target = Context;

    fn deref(&self) -> &Context {
        self.ctx
    }
}

impl<'a, C> DerefMut for ProgressCallbackGuard<'a, C> {
    fn deref_mut(&mut self) -> &mut Context {
        self.ctx
    }
}

extern fn passphrase_callback<C: PassphraseCallback>(hook: *mut libc::c_void,
                                                     uid_hint: *const libc::c_char,
                                                     info: *const libc::c_char,
                                                     was_bad: libc::c_int,
                                                     fd: libc::c_int) -> sys::gpgme_error_t {
    use std::io::prelude::*;

    let cb = hook as *mut C;
    unsafe {
        let uid_hint = utils::from_cstr(uid_hint);
        let info = utils::from_cstr(info);
        let mut writer = FdWriter::new(fd);
        (*cb).read(uid_hint, info, was_bad != 0, &mut writer).err().map_or(0, |err| err.raw())
    }
}

extern fn progress_callback<C: ProgressCallback>(hook: *mut libc::c_void,
                                                 what: *const libc::c_char,
                                                 typ: libc::c_int,
                                                 current: libc::c_int,
                                                 total: libc::c_int) {
    let cb = hook as *mut C;
    unsafe {
        let what = utils::from_cstr(what);
        (*cb).report(what, typ as isize, current as isize, total as isize);
    }
}
