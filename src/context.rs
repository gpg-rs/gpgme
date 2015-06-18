use std::ffi::CString;
use std::mem;
use std::ptr;

use libc;

use enum_primitive::FromPrimitive;

use gpgme_sys as sys;

use {Protocol, Token};
use error::{Result, Error};
use keys::Key;
use engine::{EngineInfo, EngineInfoIter};
use data::Data;
use ops;

/// A context for cryptographic operations
#[derive(Debug)]
pub struct Context {
    raw: sys::gpgme_ctx_t,
    lib: Token,
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
        let result = unsafe {
            sys::gpgme_new(&mut ctx)
        };
        if result == 0 {
            Ok(Context { raw: ctx, lib: lib })
        } else {
            Err(Error::new(result))
        }
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
        let result = unsafe {
            sys::gpgme_set_protocol(self.raw, proto as sys::gpgme_protocol_t)
        };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::new(result))
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

    pub fn set_engine_info(&mut self, proto: Protocol, file_name: Option<String>,
                           home_dir: Option<String>) -> Result<()> {
        let file_name = match file_name {
            Some(v) => Some(try!(CString::new(v))),
            None => None,
        };
        let home_dir = match home_dir {
            Some(v) => Some(try!(CString::new(v))),
            None => None,
        };
        let result = unsafe {
            let file_name = file_name.map_or(ptr::null(), |s| s.as_ptr());
            let home_dir = home_dir.map_or(ptr::null(), |s| s.as_ptr());
            sys::gpgme_ctx_set_engine_info(self.raw, proto as sys::gpgme_protocol_t,
                                           file_name, home_dir)
        };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::new(result))
        }
    }

    pub fn key_list_mode(&self) -> ops::KeyListMode {
        unsafe {
            ops::KeyListMode::from_bits_truncate(sys::gpgme_get_keylist_mode(self.raw))
        }
    }

    pub fn set_key_list_mode(&mut self, mask: ops::KeyListMode) -> Result<()> {
        let result = unsafe {
            let old = sys::gpgme_get_keylist_mode(self.raw);
            sys::gpgme_set_keylist_mode(self.raw, (old & !ops::KeyListMode::all().bits()) |
                                        mask.bits())
        };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::new(result))
        }
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
            let result = sys::gpgme_get_key(self.raw, pattern.as_ptr(),
                                            &mut key, false as libc::c_int);
            if result == 0 {
                Ok(Key::from_raw(key))
            } else {
                Err(Error::new(result))
            }
        }
    }

    pub fn find_secret_key<S: Into<String>>(&self, pattern: S) -> Result<Key> {
        let mut key: sys::gpgme_key_t = ptr::null_mut();
        let pattern = try!(CString::new(pattern.into()));
        unsafe {
            let result = sys::gpgme_get_key(self.raw, pattern.as_ptr(),
                                            &mut key, true as libc::c_int);
            if result == 0 {
                Ok(Key::from_raw(key))
            } else {
                Err(Error::new(result))
            }
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
        unsafe {
            let result = sys::gpgme_op_keylist_result(self.raw);
            if !result.is_null() {
                sys::gpgme_result_ref(result as *mut libc::c_void);
                Some(ops::KeyListResult::from_raw(result))
            } else {
                None
            }
        }
    }

    pub fn generate_key<S: Into<String>>(&mut self, params: S, public: Option<&mut Data>,
                        secret: Option<&mut Data>) -> Result<ops::KeyGenerateResult> {
        let params = try!(CString::new(params.into()));
        let public = public.map(|d| d.as_raw()).unwrap_or(ptr::null_mut());
        let secret = secret.map(|d| d.as_raw()).unwrap_or(ptr::null_mut());
        let result = unsafe {
            sys::gpgme_op_genkey(self.raw, params.as_ptr(), public, secret)
        };
        if result == 0 {
            Ok(self.generate_key_result().unwrap())
        } else {
            Err(Error::new(result))
        }
    }

    pub fn generate_key_result(&self) -> Option<ops::KeyGenerateResult> {
        unsafe {
            let result = sys::gpgme_op_genkey_result(self.raw);
            if !result.is_null() {
                sys::gpgme_result_ref(result as *mut libc::c_void);
                Some(ops::KeyGenerateResult::from_raw(result))
            } else {
                None
            }
        }
    }

    pub fn import(&mut self, key_data: &mut Data) -> Result<ops::ImportResult> {
        let result = unsafe {
            sys::gpgme_op_import(self.raw, key_data.as_raw())
        };
        if result == 0 {
            Ok(self.import_result().unwrap())
        } else {
            Err(Error::new(result))
        }
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
        let result = unsafe {
            sys::gpgme_op_import_keys(self.raw, keys)
        };
        if result == 0 {
            Ok(self.import_result().unwrap())
        } else {
            Err(Error::new(result))
        }
    }

    pub fn import_result(&self) -> Option<ops::ImportResult> {
        unsafe {
            let result = sys::gpgme_op_import_result(self.raw);
            if !result.is_null() {
                sys::gpgme_result_ref(result as *mut libc::c_void);
                Some(ops::ImportResult::from_raw(result))
            } else {
                None
            }
        }
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
        let result = match strings.len() {
            0 | 1 => unsafe {
                let pattern = strings.first().map_or(ptr::null(), |s| s.as_ptr());
                sys::gpgme_op_export(self.raw, pattern, mode.bits(), data)
            },
            _ => unsafe {
                let mut ptrs: Vec<_> = strings.iter().map(|s| s.as_ptr()).collect();
                ptrs.push(ptr::null());
                sys::gpgme_op_export_ext(self.raw, ptrs.as_mut_ptr(), mode.bits(), data)
            },
        };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::new(result))
        }
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
        let result = unsafe {
            sys::gpgme_op_export_keys(self.raw, keys, mode.bits(), data)
        };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::new(result))
        }
    }

    pub fn clear_signers(&mut self) {
        unsafe {
            sys::gpgme_signers_clear(self.raw)
        }
    }

    pub fn add_signer(&mut self, key: &Key) -> Result<()> {
        let result = unsafe {
            sys::gpgme_signers_add(self.raw, key.as_raw())
        };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::new(result))
        }
    }

    pub fn signers(&self) -> SignersIter {
        SignersIter::new(self)
    }

    pub fn sign(&mut self, mode: ops::SignMode, plain: &mut Data,
                signature: &mut Data) -> Result<ops::SignResult> {
        let result = unsafe {
            sys::gpgme_op_sign(self.raw, plain.as_raw(), signature.as_raw(),
                               mode as sys::gpgme_sig_mode_t)
        };
        if result == 0 {
            Ok(self.sign_result().unwrap())
        } else {
            Err(Error::new(result))
        }
    }

    pub fn sign_result(&self) -> Option<ops::SignResult> {
        unsafe {
            let result = sys::gpgme_op_sign_result(self.raw);
            if !result.is_null() {
                sys::gpgme_result_ref(result as *mut libc::c_void);
                Some(ops::SignResult::from_raw(result))
            } else {
                None
            }
        }
    }

    pub fn verify(&mut self, signature: &mut Data, signed: Option<&mut Data>,
                  plain: Option<&mut Data>) -> Result<ops::VerifyResult> {
        let signed = signed.map_or(ptr::null_mut(), |d| d.as_raw());
        let plain = plain.map_or(ptr::null_mut(), |d| d.as_raw());
        let result = unsafe {
            sys::gpgme_op_verify(self.raw, signature.as_raw(), signed, plain)
        };
        if result == 0 {
            Ok(self.verify_result().unwrap())
        } else {
            Err(Error::new(result))
        }
    }

    pub fn verify_result(&self) -> Option<ops::VerifyResult> {
        unsafe {
            let result = sys::gpgme_op_verify_result(self.raw);
            if !result.is_null() {
                sys::gpgme_result_ref(result as *mut libc::c_void);
                Some(ops::VerifyResult::from_raw(result))
            } else {
                None
            }
        }
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
        let result = unsafe {
            sys::gpgme_op_encrypt(self.raw, keys, flags.bits(), plain.as_raw(), cipher.as_raw())
        };
        if result == 0 {
            Ok(self.encrypt_result().unwrap())
        } else {
            Err(Error::new(result))
        }
    }

    pub fn encrypt_result(&self) -> Option<ops::EncryptResult> {
        unsafe {
            let result = sys::gpgme_op_encrypt_result(self.raw);
            if !result.is_null() {
                sys::gpgme_result_ref(result as *mut libc::c_void);
                Some(ops::EncryptResult::from_raw(result))
            } else {
                None
            }
        }
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
        let result = unsafe {
            sys::gpgme_op_decrypt(self.raw, cipher.as_raw(), plain.as_raw())
        };
        if result == 0 {
            Ok(self.decrypt_result().unwrap())
        } else {
            Err(Error::new(result))
        }
    }

    pub fn decrypt_result(&self) -> Option<ops::DecryptResult> {
        unsafe {
            let result = sys::gpgme_op_decrypt_result(self.raw);
            if !result.is_null() {
                sys::gpgme_result_ref(result as *mut libc::c_void);
                Some(ops::DecryptResult::from_raw(result))
            } else {
                None
            }
        }
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
        let result = unsafe {
            sys::gpgme_op_encrypt_sign(self.raw, keys, flags.bits(), plain.as_raw(), cipher.as_raw())
        };
        if result == 0 {
            Ok((self.encrypt_result().unwrap(), self.sign_result().unwrap()))
        } else {
            Err(Error::new(result))
        }
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
        let result = unsafe {
            sys::gpgme_op_decrypt_verify(self.raw, cipher.as_raw(), plain.as_raw())
        };
        if result == 0 {
            Ok((self.decrypt_result().unwrap(), self.verify_result().unwrap()))
        } else {
            Err(Error::new(result))
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            sys::gpgme_release(self.raw)
        }
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
        let result = match strings.len() {
            0 | 1 => unsafe {
                let pattern = strings.first().map_or(ptr::null(), |s| s.as_ptr());
                sys::gpgme_op_keylist_start(ctx.as_raw(), pattern, secret_only as libc::c_int)
            },
            _ => unsafe {
                let mut ptrs: Vec<_> = strings.iter().map(|s| s.as_ptr()).collect();
                ptrs.push(ptr::null());
                sys::gpgme_op_keylist_ext_start(ctx.as_raw(), ptrs.as_mut_ptr(),
                                                secret_only as libc::c_int, 0)
            },
        };
        if result == 0 {
            Ok(Keys { ctx: ctx })
        } else {
            Err(Error::new(result))
        }
    }

    pub fn result(self) -> Result<ops::KeyListResult> {
        let result = unsafe {
            sys::gpgme_op_keylist_end(self.ctx.as_raw())
        };
        let result = if result == 0 {
            Ok(self.ctx.key_list_result().unwrap())
        } else {
            Err(Error::new(result))
        };
        mem::forget(self);
        result
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
    count: usize,
}

impl<'a> SignersIter<'a> {
    fn new<'b>(ctx: &'b Context) -> SignersIter<'b> {
        let count = unsafe {
            sys::gpgme_signers_count(ctx.as_raw()) as usize
        };
        SignersIter { ctx: ctx, current: 0, count: count }
    }
}

impl<'a> Iterator for SignersIter<'a> {
    type Item = Key;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current < self.count {
            unsafe {
                let key = sys::gpgme_signers_enum(self.ctx.as_raw(), self.current as libc::c_int);
                self.current += 1;
                Some(Key::from_raw(key))
            }
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.count - self.current;
        (size, Some(size))
    }

    fn count(self) -> usize {
        self.size_hint().0
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        if (n <= self.count) && (self.current < (self.count - n)) {
            let current = self.current + n;
            self.current += n + 1;
            unsafe {
                let key = sys::gpgme_signers_enum(self.ctx.as_raw(), current as libc::c_int);
                Some(Key::from_raw(key))
            }
        } else {
            self.current = self.count;
            None
        }
    }

    fn last(mut self) -> Option<Self::Item> {
        self.next_back()
    }
}

impl<'a> DoubleEndedIterator for SignersIter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.count > self.current {
            unsafe {
                self.count -= 1;
                let key = sys::gpgme_signers_enum(self.ctx.as_raw(), self.count as libc::c_int);
                Some(Key::from_raw(key))
            }
        } else {
            None
        }
    }
}

impl<'a> ExactSizeIterator for SignersIter<'a> {}
