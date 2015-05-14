use std::ffi::{CStr, CString};
use std::fmt;
use std::ptr;
use std::str;

use libc;

use enum_primitive::FromPrimitive;

use gpgme_sys as sys;

use error::{Result, Error};
use keys::Key;
use data::Data;
use ops;

enum_from_primitive! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub enum Protocol {
        OpenPgp = 0,
        Cms = 1,
        GpgConf = 2,
        Assuan = 3,
        G13 = 4,
        UiServer = 5,
        Default  = 254,
        Unknown = 255,
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let proto = sys::gpgme_protocol_t::from_u32(*self as u32);
        let name = unsafe {
            proto.map(|p| CStr::from_ptr(sys::gpgme_get_protocol_name(p) as *const _).to_bytes())
        };
        write!(f, "{}", name.and_then(|b| str::from_utf8(b).ok()).unwrap_or("Unknown"))
    }
}

#[derive(Debug)]
pub struct Context {
    raw: sys::gpgme_ctx_t,
}

impl Context {
    pub fn new() -> Result<Context> {
        let mut ctx: sys::gpgme_ctx_t = ptr::null_mut();
        let result = unsafe {
            sys::gpgme_new(&mut ctx)
        };
        if result == 0 {
            Ok(Context { raw: ctx })
        } else {
            Err(Error::new(result))
        }
    }

    pub unsafe fn from_raw(ctx: sys::gpgme_ctx_t) -> Context {
        Context { raw: ctx }
    }

    pub unsafe fn raw(&self) -> sys::gpgme_ctx_t {
        self.raw
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
            Protocol::from_u32(sys::gpgme_get_protocol(self.raw) as u32).unwrap_or(Protocol::Unknown)
        }
    }

    pub fn set_protocol(&mut self, proto: Protocol) -> Result<()> {
        let result = unsafe {
            sys::gpgme_set_protocol(self.raw, sys::gpgme_protocol_t::from_u32(proto as u32).unwrap())
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
            sys::gpgme_set_keylist_mode(self.raw, (old & !ops::KeyListMode::all().bits()) | mask.bits())
        };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::new(result))
        }
    }

    pub fn find_key(&self, pattern: &str) -> Result<Key> {
        let mut key: sys::gpgme_key_t = ptr::null_mut();
        let pattern = try!(CString::new(pattern));
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

    pub fn find_secret_key(&self, pattern: &str) -> Result<Key> {
        let mut key: sys::gpgme_key_t = ptr::null_mut();
        let pattern = try!(CString::new(pattern));
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

    pub fn find_keys(&mut self, pattern: Option<&str>) -> Result<KeyIter> {
        KeyIter::new(self, pattern, false)
    }

    pub fn find_secret_keys(&mut self, pattern: Option<&str>) -> Result<KeyIter> {
        KeyIter::new(self, pattern, true)
    }

    pub fn generate_key(&mut self, params: &str, public: Option<&mut Data>,
                        secret: Option<&mut Data>) -> Result<ops::KeyGenerateResult> {
        let params = try!(CString::new(params));
        let result = unsafe {
            let public = public.map(|d| d.raw()).unwrap_or(ptr::null_mut());
            let secret = secret.map(|d| d.raw()).unwrap_or(ptr::null_mut());
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
            sys::gpgme_op_import(self.raw, key_data.raw())
        };
        if result == 0 {
            Ok(self.import_result().unwrap())
        } else {
            Err(Error::new(result))
        }
    }

    pub fn import_keys(&mut self, keys: &[&Key]) -> Result<ops::ImportResult> {
        let result = unsafe {
            let mut ptrs: Vec<sys::gpgme_key_t>;
            let keys = if !keys.is_empty() {
                ptrs = keys.iter().map(|k| k.raw()).collect();
                ptrs.push(ptr::null_mut());
                ptrs.as_mut_ptr()
            } else {
                ptr::null_mut()
            };
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

    pub fn export(&mut self, pattern: Option<&str>, mode: ops::ExportMode,
                  data: Option<&mut Data>) -> Result<()> {
        let pattern = match pattern {
            Some(p) => Some(try!(CString::new(p))),
            None => None
        };
        let result = unsafe {
            let data = data.map_or(ptr::null_mut(), |d| d.raw());
            sys::gpgme_op_export(self.raw, pattern.map_or(ptr::null(), |s| s.as_ptr()),
                                 mode.bits(), data)
        };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::new(result))
        }
    }

    pub fn export_ext(&mut self, patterns: &[&str], mode: ops::ExportMode,
                           data: Option<&mut Data>) -> Result<()> {
        let mut strings = Vec::new();
        let mut ptrs: Vec<*const libc::c_char>;
        let patterns = if !patterns.is_empty() {
            for pattern in patterns {
                strings.push(try!(CString::new(*pattern)));
            }
            ptrs = strings.iter().map(|s| s.as_ptr()).collect();
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        let result = unsafe {
            let data = data.map_or(ptr::null_mut(), |d| d.raw());
            sys::gpgme_op_export_ext(self.raw, patterns, mode.bits(), data)
        };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::new(result))
        }
    }

    pub fn export_keys(&mut self, keys: &[&Key], mode: ops::ExportMode,
                       data: Option<&mut Data>) -> Result<()> {
        let result = unsafe {
            let mut ptrs: Vec<sys::gpgme_key_t>;
            let keys = if !keys.is_empty() {
                ptrs = keys.iter().map(|k| k.raw()).collect();
                ptrs.push(ptr::null_mut());
                ptrs.as_mut_ptr()
            } else {
                ptr::null_mut()
            };
            let data = data.map_or(ptr::null_mut(), |d| d.raw());
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
            sys::gpgme_signers_add(self.raw, key.raw())
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
            let mode = sys::gpgme_sig_mode_t::from_u32(mode as u32).unwrap();
            sys::gpgme_op_sign(self.raw, plain.raw(), signature.raw(), mode)
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
        let result = unsafe {
            let signed = signed.map_or(ptr::null_mut(), |d| d.raw());
            let plain = plain.map_or(ptr::null_mut(), |d| d.raw());
            sys::gpgme_op_verify(self.raw, signature.raw(), signed, plain)
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

    pub fn encrypt(&mut self, recp: &[&Key], flags: ops::EncryptFlags,
                   plain: &mut Data, cipher: &mut Data) -> Result<ops::EncryptResult> {
        let result = unsafe {
            let mut ptrs: Vec<sys::gpgme_key_t>;
            let keys = if !recp.is_empty() {
                ptrs = recp.iter().map(|k| k.raw()).collect();
                ptrs.push(ptr::null_mut());
                ptrs.as_mut_ptr()
            } else {
                ptr::null_mut()
            };
            sys::gpgme_op_encrypt(self.raw, keys, flags.bits(), plain.raw(), cipher.raw())
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

    pub fn encrypt_and_sign(&mut self, recp: &[&Key], flags: ops::EncryptFlags,
                            plain: &mut Data, cipher: &mut Data) -> Result<ops::EncryptResult> {
        let result = unsafe {
            let mut ptrs: Vec<sys::gpgme_key_t>;
            let keys = if !recp.is_empty() {
                ptrs = recp.iter().map(|k| k.raw()).collect();
                ptrs.push(ptr::null_mut());
                ptrs.as_mut_ptr()
            } else {
                ptr::null_mut()
            };
            sys::gpgme_op_encrypt_sign(self.raw, keys, flags.bits(), plain.raw(), cipher.raw())
        };
        if result == 0 {
            Ok(self.encrypt_result().unwrap())
        } else {
            Err(Error::new(result))
        }
    }

    pub fn decrypt(&mut self, cipher: &mut Data, plain: &mut Data) -> Result<ops::DecryptResult> {
        let result = unsafe {
            sys::gpgme_op_decrypt(self.raw, cipher.raw(), plain.raw())
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

    pub fn decrypt_and_verify(&mut self, cipher: &mut Data, plain: &mut Data)
            -> Result<(ops::DecryptResult, ops::VerifyResult)> {
        let result = unsafe {
            sys::gpgme_op_decrypt_verify(self.raw, cipher.raw(), plain.raw())
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

pub struct KeyIter<'a> {
    ctx: &'a mut Context,
}

impl<'a> KeyIter<'a> {
    fn new<'b>(ctx: &'b mut Context, pattern: Option<&str>,
               secret_only: bool) -> Result<KeyIter<'b>> {
        let pattern = match pattern {
            Some(p) => Some(try!(CString::new(p))),
            None => None
        };
        let result = unsafe {
            sys::gpgme_op_keylist_start(ctx.raw, pattern.map_or(ptr::null(), |s| s.as_ptr()),
                                        secret_only as libc::c_int)
        };
        if result == 0 {
            Ok(KeyIter { ctx: ctx })
        } else {
            Err(Error::new(result))
        }
    }
}

impl<'a> Drop for KeyIter<'a> {
    fn drop(&mut self) {
        unsafe {
            sys::gpgme_op_keylist_end(self.ctx.raw);
        }
    }
}

impl<'a> Iterator for KeyIter<'a> {
    type Item = Result<Key>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut key: sys::gpgme_key_t = ptr::null_mut();
        unsafe {
            let result = sys::gpgme_op_keylist_next(self.ctx.raw, &mut key);
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
            sys::gpgme_signers_count(ctx.raw()) as usize
        };
        SignersIter { ctx: ctx, current: 0, count: count }
    }
}

impl<'a> Iterator for SignersIter<'a> {
    type Item = Key;

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.count - self.current;
        (size, Some(size))
    }

    fn count(self) -> usize {
        self.size_hint().0
    }

    fn next(&mut self) -> Option<Self::Item> {
        if self.current < self.count {
            unsafe {
                let key = sys::gpgme_signers_enum(self.ctx.raw(), self.current as libc::c_int);
                self.current += 1;
                Some(Key::from_raw(key))
            }
        } else {
            None
        }
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        if (n <= self.count) && (self.current < (self.count - n)) {
            let current = self.current + n;
            self.current += n + 1;
            unsafe {
                let key = sys::gpgme_signers_enum(self.ctx.raw(), current as libc::c_int);
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
                let key = sys::gpgme_signers_enum(self.ctx.raw(), self.count as libc::c_int);
                Some(Key::from_raw(key))
            }
        } else {
            None
        }
    }
}

impl<'a> ExactSizeIterator for SignersIter<'a> {}
