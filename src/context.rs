use std::{mem, ptr, result};
use std::borrow::BorrowMut;
use std::ffi::CStr;
use std::fmt;
use std::str::Utf8Error;
use std::time::{SystemTime, UNIX_EPOCH};

use conv::{UnwrapOrSaturate, ValueInto};
use ffi;
use libc;

use {
    Data, EditInteractor, Error, ExportMode, IntoData, Key, KeyListMode, NonZero,
    PassphraseProvider, ProgressHandler, Protocol, Result, SignMode, TrustItem,
};
use {callbacks, edit, results};
use engine::EngineInfo;
use notation::SignatureNotations;
use utils::CStrArgument;

/// A context for cryptographic operations
#[must_use]
pub struct Context(NonZero<ffi::gpgme_ctx_t>);

impl Drop for Context {
    #[inline]
    fn drop(&mut self) {
        unsafe { ffi::gpgme_release(self.as_raw()) }
    }
}

impl Context {
    impl_wrapper!(Context: ffi::gpgme_ctx_t);

    #[inline]
    fn new() -> Result<Self> {
        ::init();
        unsafe {
            let mut ctx = ptr::null_mut();
            return_err!(ffi::gpgme_new(&mut ctx));
            Ok(Context::from_raw(ctx))
        }
    }

    #[inline]
    pub fn from_protocol(proto: Protocol) -> Result<Self> {
        let ctx = Context::new()?;
        unsafe {
            return_err!(ffi::gpgme_set_protocol(ctx.as_raw(), proto.raw()));
        }
        Ok(ctx)
    }

    #[inline]
    pub fn protocol(&self) -> Protocol {
        unsafe { Protocol::from_raw(ffi::gpgme_get_protocol(self.as_raw())) }
    }

    #[inline]
    pub fn armor(&self) -> bool {
        unsafe { ffi::gpgme_get_armor(self.as_raw()) != 0 }
    }

    #[inline]
    pub fn set_armor(&mut self, enabled: bool) {
        unsafe {
            ffi::gpgme_set_armor(self.as_raw(), if enabled { 1 } else { 0 });
        }
    }

    #[inline]
    pub fn text_mode(&self) -> bool {
        unsafe { ffi::gpgme_get_textmode(self.as_raw()) != 0 }
    }

    #[inline]
    pub fn set_text_mode(&mut self, enabled: bool) {
        unsafe {
            ffi::gpgme_set_textmode(self.as_raw(), if enabled { 1 } else { 0 });
        }
    }

    #[inline]
    pub fn offline(&self) -> bool {
        unsafe { ffi::gpgme_get_offline(self.as_raw()) != 0 }
    }

    #[inline]
    pub fn set_offline(&mut self, enabled: bool) {
        unsafe {
            ffi::gpgme_set_offline(self.as_raw(), if enabled { 1 } else { 0 });
        }
    }

    #[inline]
    pub fn get_flag<S>(&self, name: S) -> result::Result<&str, Option<Utf8Error>>
    where S: CStrArgument {
        self.get_flag_raw(name)
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn get_flag_raw<S>(&self, name: S) -> Option<&CStr>
    where S: CStrArgument {
        let name = name.into_cstr();
        unsafe {
            ffi::gpgme_get_ctx_flag(self.as_raw(), name.as_ref().as_ptr())
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn set_flag<S1, S2>(&mut self, name: S1, value: S2) -> Result<()>
    where
        S1: CStrArgument,
        S2: CStrArgument, {
        let name = name.into_cstr();
        let value = value.into_cstr();
        unsafe {
            return_err!(ffi::gpgme_set_ctx_flag(
                self.as_raw(),
                name.as_ref().as_ptr(),
                value.as_ref().as_ptr(),
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn engine_info(&self) -> EngineInfo {
        unsafe { EngineInfo::from_raw(ffi::gpgme_ctx_get_engine_info(self.as_raw())) }
    }

    #[inline]
    pub fn set_engine_path<S>(&mut self, path: S) -> Result<()>
    where S: CStrArgument {
        let path = path.into_cstr();
        let home_dir = self.engine_info()
            .home_dir_raw()
            .map_or(ptr::null(), CStr::as_ptr);
        unsafe {
            return_err!(ffi::gpgme_ctx_set_engine_info(
                self.as_raw(),
                self.protocol().raw(),
                path.as_ref().as_ptr(),
                home_dir,
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn set_engine_home_dir<S>(&mut self, home_dir: S) -> Result<()>
    where S: CStrArgument {
        let path = self.engine_info()
            .path_raw()
            .map_or(ptr::null(), CStr::as_ptr);
        let home_dir = home_dir.into_cstr();
        unsafe {
            return_err!(ffi::gpgme_ctx_set_engine_info(
                self.as_raw(),
                self.protocol().raw(),
                path,
                home_dir.as_ref().as_ptr(),
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn set_engine_info<S1, S2>(
        &mut self, path: Option<S1>, home_dir: Option<S2>
    ) -> Result<()>
    where
        S1: CStrArgument,
        S2: CStrArgument, {
        let path = path.map(S1::into_cstr);
        let home_dir = home_dir.map(S2::into_cstr);
        unsafe {
            let path = path.as_ref().map_or(ptr::null(), |s| s.as_ref().as_ptr());
            let home_dir = home_dir
                .as_ref()
                .map_or(ptr::null(), |s| s.as_ref().as_ptr());
            return_err!(ffi::gpgme_ctx_set_engine_info(
                self.as_raw(),
                self.protocol().raw(),
                path,
                home_dir,
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn pinentry_mode(self) -> ::PinentryMode {
        unsafe { ::PinentryMode::from_raw(ffi::gpgme_get_pinentry_mode(self.as_raw())) }
    }

    #[inline]
    pub fn set_pinentry_mode(&mut self, mode: ::PinentryMode) -> Result<()> {
        require_gpgme_ver! {
            (1, 7) => {} else {
                if (self.protocol() == Protocol::OpenPgp) &&
                    !self.engine_info().check_version("2.1.0") {
                    return Ok(());
                }
            }
        }
        unsafe {
            return_err!(ffi::gpgme_set_pinentry_mode(self.as_raw(), mode.raw()));
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
    pub fn with_passphrase_provider<P, F, R>(&mut self, provider: P, f: F) -> R
    where
        P: PassphraseProvider,
        F: FnOnce(&mut Context) -> R, {
        unsafe {
            let mut old = (None, ptr::null_mut());
            ffi::gpgme_get_passphrase_cb(self.as_raw(), &mut old.0, &mut old.1);
            let mut wrapper = callbacks::PassphraseProviderWrapper {
                ctx: self.as_raw(),
                old: old,
                state: Some(Ok(provider)),
            };
            ffi::gpgme_set_passphrase_cb(
                self.as_raw(),
                Some(callbacks::passphrase_cb::<P>),
                (&mut wrapper as *mut _) as *mut _,
            );
            f(self)
        }
    }

    pub fn with_progress_handler<H, F, R>(&mut self, handler: H, f: F) -> R
    where
        H: ProgressHandler,
        F: FnOnce(&mut Context) -> R, {
        unsafe {
            let mut old = (None, ptr::null_mut());
            ffi::gpgme_get_progress_cb(self.as_raw(), &mut old.0, &mut old.1);
            let mut wrapper = callbacks::ProgressHandlerWrapper {
                ctx: self.as_raw(),
                old: old,
                state: Some(Ok(handler)),
            };
            ffi::gpgme_set_progress_cb(
                self.as_raw(),
                Some(callbacks::progress_cb::<H>),
                (&mut wrapper as *mut _) as *mut _,
            );
            f(self)
        }
    }

    pub fn with_status_handler<H, F, R>(&mut self, handler: H, f: F) -> R
    where
        H: ::StatusHandler,
        F: FnOnce(&mut Context) -> R, {
        unsafe {
            let mut old = (None, ptr::null_mut());
            ffi::gpgme_get_status_cb(self.as_raw(), &mut old.0, &mut old.1);
            let mut wrapper = callbacks::StatusHandlerWrapper {
                ctx: self.as_raw(),
                old: old,
                state: Some(Ok(handler)),
            };
            ffi::gpgme_set_status_cb(
                self.as_raw(),
                Some(callbacks::status_cb::<H>),
                (&mut wrapper as *mut _) as *mut _,
            );
            f(self)
        }
    }

    #[inline]
    pub fn find_trust_items<S: CStrArgument>(
        &mut self, pattern: S, max_level: i32
    ) -> Result<TrustItems> {
        let pattern = pattern.into_cstr();
        unsafe {
            return_err!(ffi::gpgme_op_trustlist_start(
                self.as_raw(),
                pattern.as_ref().as_ptr(),
                max_level.into(),
            ));
        }
        Ok(TrustItems { ctx: self })
    }

    #[inline]
    pub fn key_list_mode(&self) -> KeyListMode {
        unsafe {
            ::KeyListMode::from_bits_truncate(ffi::gpgme_get_keylist_mode(self.as_raw()))
        }
    }

    #[inline]
    pub fn add_key_list_mode(&mut self, mask: KeyListMode) -> Result<()> {
        unsafe {
            let old = ffi::gpgme_get_keylist_mode(self.as_raw());
            return_err!(ffi::gpgme_set_keylist_mode(
                self.as_raw(),
                mask.bits() | (old & !KeyListMode::all().bits()),
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn set_key_list_mode(&mut self, mode: KeyListMode) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_set_keylist_mode(self.as_raw(), mode.bits()));
        }
        Ok(())
    }

    #[inline]
    pub fn keys(&mut self) -> Result<Keys> {
        Keys::new(self, None::<String>, false)
    }

    #[inline]
    pub fn secret_keys(&mut self) -> Result<Keys> {
        Keys::new(self, None::<String>, true)
    }

    #[inline]
    pub fn get_key(&mut self, key: &Key) -> Result<Key> {
        match key.fingerprint_raw() {
            Some(fpr) => self.find_key(fpr),
            None => Err(Error::AMBIGUOUS_NAME),
        }
    }

    #[inline]
    pub fn get_secret_key(&mut self, key: &Key) -> Result<Key> {
        match key.fingerprint_raw() {
            Some(fpr) => self.find_secret_key(fpr),
            None => Err(Error::AMBIGUOUS_NAME),
        }
    }

    /// Returns the public key with the specified fingerprint, if such a key can
    /// be found. Otherwise, an error is returned.
    #[inline]
    pub fn find_key<S: CStrArgument>(&self, fingerprint: S) -> Result<Key> {
        let fingerprint = fingerprint.into_cstr();
        unsafe {
            let mut key = ptr::null_mut();
            return_err!(ffi::gpgme_get_key(
                self.as_raw(),
                fingerprint.as_ref().as_ptr(),
                &mut key,
                0,
            ));
            Ok(Key::from_raw(key))
        }
    }

    /// Returns the secret key with the specified fingerprint, if such a key can
    /// be found. Otherwise, an error is returned.
    #[inline]
    pub fn find_secret_key<S: CStrArgument>(&self, fingerprint: S) -> Result<Key> {
        let fingerprint = fingerprint.into_cstr();
        unsafe {
            let mut key = ptr::null_mut();
            return_err!(ffi::gpgme_get_key(
                self.as_raw(),
                fingerprint.as_ref().as_ptr(),
                &mut key,
                1,
            ));
            Ok(Key::from_raw(key))
        }
    }

    /// Returns an iterator for a list of all public keys matching one or more of the
    /// specified patterns.
    #[inline]
    pub fn find_keys<I>(&mut self, patterns: I) -> Result<Keys>
    where
        I: IntoIterator,
        I::Item: CStrArgument, {
        Keys::new(self, patterns, false)
    }

    /// Returns an iterator for a list of all secret keys matching one or more of the
    /// specified patterns.
    #[inline]
    pub fn find_secret_keys<I>(&mut self, patterns: I) -> Result<Keys>
    where
        I: IntoIterator,
        I::Item: CStrArgument, {
        Keys::new(self, patterns, true)
    }

    /// Returns an iterator over the keys encoded in the specified source.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use gpgme::{Context, Data, Protocol};
    ///
    /// let mut ctx = Context::from_protocol(Protocol::OpenPgp).unwrap();
    /// let mut keyring = Data::load("somefile").unwrap();
    /// for key in ctx.read_keys(&mut keyring).unwrap() {
    ///     println!("{:?}", key);
    /// }
    /// ```
    #[inline]
    pub fn read_keys<'d, D>(&mut self, src: D) -> Result<Keys<D::Output>>
    where D: IntoData<'d> {
        Keys::from_data(self, src)
    }

    #[inline]
    pub fn generate_key<'d1, 'd2, S, D1, D2>(
        &mut self, params: S, public: Option<D1>, secret: Option<D2>
    ) -> Result<results::KeyGenerationResult>
    where
        S: CStrArgument,
        D1: IntoData<'d1>,
        D2: IntoData<'d2>, {
        let params = params.into_cstr();
        let mut public = public.map_or(Ok(None), |d| d.into_data().map(Some))?;
        let mut secret = secret.map_or(Ok(None), |d| d.into_data().map(Some))?;
        unsafe {
            return_err!(ffi::gpgme_op_genkey(
                self.as_raw(),
                params.as_ref().as_ptr(),
                public
                    .as_mut()
                    .map_or(ptr::null_mut(), |d| d.borrow_mut().as_raw()),
                secret
                    .as_mut()
                    .map_or(ptr::null_mut(), |d| d.borrow_mut().as_raw()),
            ));
        }
        Ok(self.get_result().unwrap())
    }

    #[inline]
    pub fn create_key<S1, S2>(
        &mut self, userid: S1, algo: S2, expires: Option<SystemTime>
    ) -> Result<results::KeyGenerationResult>
    where
        S1: CStrArgument,
        S2: CStrArgument, {
        self.create_key_with_flags(userid, algo, expires, ::CreateKeyFlags::empty())
    }

    #[inline]
    pub fn create_key_with_flags<S1, S2>(
        &mut self, userid: S1, algo: S2, expires: Option<SystemTime>, flags: ::CreateKeyFlags
    ) -> Result<results::KeyGenerationResult>
    where
        S1: CStrArgument,
        S2: CStrArgument, {
        let userid = userid.into_cstr();
        let algo = algo.into_cstr();
        let expires = expires
            .and_then(|e| e.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |e| e.as_secs().value_into().unwrap_or_saturate());

        unsafe {
            return_err!(ffi::gpgme_op_createkey(
                self.as_raw(),
                userid.as_ref().as_ptr(),
                algo.as_ref().as_ptr(),
                0,
                expires,
                ptr::null_mut(),
                flags.bits(),
            ));
        }
        Ok(self.get_result().unwrap())
    }

    #[inline]
    pub fn create_subkey<S>(
        &mut self, key: &Key, algo: S, expires: Option<SystemTime>
    ) -> Result<results::KeyGenerationResult>
    where S: CStrArgument {
        self.create_subkey_with_flags(key, algo, expires, ::CreateKeyFlags::empty())
    }

    #[inline]
    pub fn create_subkey_with_flags<S>(
        &mut self, key: &Key, algo: S, expires: Option<SystemTime>, flags: ::CreateKeyFlags
    ) -> Result<results::KeyGenerationResult>
    where S: CStrArgument {
        let algo = algo.into_cstr();
        let expires = expires
            .and_then(|e| e.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |e| e.as_secs().value_into().unwrap_or_saturate());

        unsafe {
            return_err!(ffi::gpgme_op_createsubkey(
                self.as_raw(),
                key.as_raw(),
                algo.as_ref().as_ptr(),
                0,
                expires,
                flags.bits(),
            ));
        }
        Ok(self.get_result().unwrap())
    }

    #[inline]
    pub fn add_uid<S>(&mut self, key: &Key, userid: S) -> Result<()>
    where S: CStrArgument {
        let userid = userid.into_cstr();
        unsafe {
            return_err!(ffi::gpgme_op_adduid(
                self.as_raw(),
                key.as_raw(),
                userid.as_ref().as_ptr(),
                0,
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn revoke_uid<S>(&mut self, key: &Key, userid: S) -> Result<()>
    where S: CStrArgument {
        let userid = userid.into_cstr();
        unsafe {
            return_err!(ffi::gpgme_op_revuid(
                self.as_raw(),
                key.as_raw(),
                userid.as_ref().as_ptr(),
                0,
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn set_uid_flag<S1, S2, S3>(
        &mut self, key: &Key, userid: S1, name: S2, value: Option<S3>
    ) -> Result<()>
    where
        S1: CStrArgument,
        S2: CStrArgument,
        S3: CStrArgument, {
        let userid = userid.into_cstr();
        let name = name.into_cstr();
        let value = value.map(CStrArgument::into_cstr);
        unsafe {
            return_err!(ffi::gpgme_op_set_uid_flag(
                self.as_raw(),
                key.as_raw(),
                userid.as_ref().as_ptr(),
                name.as_ref().as_ptr(),
                value.as_ref().map_or(ptr::null(), |s| s.as_ref().as_ptr()),
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn sign_key<I>(
        &mut self, key: &Key, userids: I, expires: Option<SystemTime>
    ) -> Result<()>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>, {
        self.sign_key_with_flags(key, userids, expires, ::KeySigningFlags::empty())
    }

    pub fn sign_key_with_flags<I>(
        &mut self, key: &Key, userids: I, expires: Option<SystemTime>, flags: ::KeySigningFlags
    ) -> Result<()>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>, {
        let (userids, flags) = {
            let mut userids = userids.into_iter();
            match (userids.next(), userids.next()) {
                (Some(first), Some(second)) => (
                    userids.fold(
                        [first.as_ref(), second.as_ref()].join(&b'\n'),
                        |mut acc, x| {
                            acc.push(b'\n');
                            acc.extend_from_slice(x.as_ref());
                            acc
                        },
                    ),
                    ::KeySigningFlags::LFSEP | flags,
                ),
                (Some(first), None) => (first.as_ref().to_owned(), flags),
                _ => panic!("no userids provided"),
            }
        };
        let userids = userids.into_cstr();
        let expires = expires
            .and_then(|e| e.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |e| e.as_secs().value_into().unwrap_or_saturate());
        unsafe {
            return_err!(ffi::gpgme_op_keysign(
                self.as_raw(),
                key.as_raw(),
                userids.as_ref().as_ptr(),
                expires,
                flags.bits(),
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn change_key_tofu_policy(&mut self, key: &Key, policy: ::TofuPolicy) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_op_tofu_policy(
                self.as_raw(),
                key.as_raw(),
                policy.raw(),
            ));
        }
        Ok(())
    }

    // Only works with GPG >= 2.0.15
    #[inline]
    pub fn change_key_passphrase(&mut self, key: &Key) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_op_passwd(self.as_raw(), key.as_raw(), 0));
        }
        Ok(())
    }

    #[inline]
    pub fn edit_key<'a, E, D>(&mut self, key: &Key, interactor: E, data: D) -> Result<()>
    where
        E: EditInteractor,
        D: IntoData<'a>, {
        let mut data = data.into_data()?;
        let mut wrapper = callbacks::EditInteractorWrapper {
            state: Some(Ok(interactor)),
            response: data.borrow_mut(),
        };
        unsafe {
            return_err!(ffi::gpgme_op_edit(
                self.as_raw(),
                key.as_raw(),
                Some(callbacks::edit_cb::<E>),
                (&mut wrapper as *mut _) as *mut _,
                (*wrapper.response).as_raw(),
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn edit_card_key<'a, E, D>(&mut self, key: &Key, interactor: E, data: D) -> Result<()>
    where
        E: EditInteractor,
        D: IntoData<'a>, {
        let mut data = data.into_data()?;
        let mut wrapper = callbacks::EditInteractorWrapper {
            state: Some(Ok(interactor)),
            response: data.borrow_mut(),
        };
        unsafe {
            return_err!(ffi::gpgme_op_card_edit(
                self.as_raw(),
                key.as_raw(),
                Some(callbacks::edit_cb::<E>),
                (&mut wrapper as *mut _) as *mut _,
                (*wrapper.response).as_raw(),
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn edit_key_with<'a, E, D>(&mut self, key: &Key, editor: E, data: D) -> Result<()>
    where
        E: edit::Editor,
        D: IntoData<'a>, {
        self.edit_key(key, edit::EditorWrapper::new(editor), data)
    }

    #[inline]
    pub fn edit_card_key_with<'a, E, D>(&mut self, key: &Key, editor: E, data: D) -> Result<()>
    where
        E: edit::Editor,
        D: IntoData<'a>, {
        self.edit_card_key(key, edit::EditorWrapper::new(editor), data)
    }

    #[inline]
    pub fn interact<'a, I, D>(&mut self, key: &Key, interactor: I, data: D) -> Result<()>
    where
        I: ::Interactor,
        D: IntoData<'a>, {
        let mut data = data.into_data()?;
        let mut wrapper = callbacks::InteractorWrapper {
            state: Some(Ok(interactor)),
            response: data.borrow_mut(),
        };
        unsafe {
            return_err!(ffi::gpgme_op_interact(
                self.as_raw(),
                key.as_raw(),
                0,
                Some(callbacks::interact_cb::<I>),
                &mut wrapper as *mut _ as *mut _,
                (*wrapper.response).as_raw(),
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn interact_with_card<'a, I, D>(
        &mut self, key: &Key, interactor: I, data: D
    ) -> Result<()>
    where
        I: ::Interactor,
        D: IntoData<'a>, {
        let mut data = data.into_data()?;
        let mut wrapper = callbacks::InteractorWrapper {
            state: Some(Ok(interactor)),
            response: data.borrow_mut(),
        };
        unsafe {
            return_err!(ffi::gpgme_op_interact(
                self.as_raw(),
                key.as_raw(),
                ffi::GPGME_INTERACT_CARD,
                Some(callbacks::interact_cb::<I>),
                &mut wrapper as *mut _ as *mut _,
                (*wrapper.response).as_raw(),
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn delete_key(&mut self, key: &Key) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_op_delete(self.as_raw(), key.as_raw(), 0));
        }
        Ok(())
    }

    #[inline]
    pub fn delete_secret_key(&mut self, key: &Key) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_op_delete(self.as_raw(), key.as_raw(), 1));
        }
        Ok(())
    }

    #[inline]
    pub fn import<'a, D>(&mut self, src: D) -> Result<results::ImportResult>
    where D: IntoData<'a> {
        let mut src = src.into_data()?;
        unsafe {
            return_err!(ffi::gpgme_op_import(
                self.as_raw(),
                src.borrow_mut().as_raw(),
            ));
        }
        Ok(self.get_result().unwrap())
    }

    pub fn import_keys<'k, I>(&mut self, keys: I) -> Result<results::ImportResult>
    where I: IntoIterator<Item = &'k Key> {
        let mut ptrs: Vec<_> = keys.into_iter().map(Key::as_raw).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            return_err!(ffi::gpgme_op_import_keys(self.as_raw(), keys));
        }
        Ok(self.get_result().unwrap())
    }

    #[inline]
    pub fn export_all_extern<'a, I>(&mut self, mode: ExportMode) -> Result<()>
    where
        I: IntoIterator,
        I::Item: CStrArgument, {
        self.export_(None::<&CStr>, mode | ExportMode::EXTERN, None)
    }

    #[inline]
    pub fn export_extern<'a, I>(&mut self, patterns: I, mode: ExportMode) -> Result<()>
    where
        I: IntoIterator,
        I::Item: CStrArgument, {
        let patterns: Vec<_> = patterns.into_iter().map(|s| s.into_cstr()).collect();
        self.export_(&patterns, mode | ExportMode::EXTERN, None)
    }

    #[inline]
    pub fn export_all<'a, D>(&mut self, mode: ExportMode, dst: D) -> Result<()>
    where D: IntoData<'a> {
        let mut dst = dst.into_data()?;
        self.export_(None::<&CStr>, mode, Some(dst.borrow_mut()))
    }

    #[inline]
    pub fn export<'a, I, D>(&mut self, patterns: I, mode: ExportMode, dst: D) -> Result<()>
    where
        I: IntoIterator,
        I::Item: CStrArgument,
        D: IntoData<'a>, {
        let mut dst = dst.into_data()?;
        let patterns: Vec<_> = patterns.into_iter().map(|s| s.into_cstr()).collect();
        self.export_(&patterns, mode, Some(dst.borrow_mut()))
    }

    fn export_<I>(&mut self, patterns: I, mode: ExportMode, dst: Option<&mut Data>) -> Result<()>
    where
        I: IntoIterator,
        I::Item: AsRef<CStr>, {
        let dst = dst.map_or(ptr::null_mut(), |d| d.as_raw());
        let mut patterns: Vec<_> = patterns.into_iter().map(|s| s.as_ref().as_ptr()).collect();
        let ptr = if !patterns.is_empty() {
            patterns.push(ptr::null());
            patterns.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            return_err!(ffi::gpgme_op_export_ext(
                self.as_raw(),
                ptr,
                mode.bits(),
                dst,
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn export_keys_extern<'k, I>(&mut self, keys: I, mode: ExportMode) -> Result<()>
    where I: IntoIterator<Item = &'k Key> {
        self.export_keys_(keys, mode | ExportMode::EXTERN, None)
    }

    #[inline]
    pub fn export_keys<'k, 'a, I, D>(&mut self, keys: I, mode: ExportMode, dst: D) -> Result<()>
    where
        I: IntoIterator<Item = &'k Key>,
        D: IntoData<'a>, {
        let mut dst = dst.into_data()?;
        self.export_keys_(keys, mode, Some(dst.borrow_mut()))
    }

    fn export_keys_<'k, I>(
        &mut self, keys: I, mode: ExportMode, dst: Option<&mut Data>
    ) -> Result<()>
    where I: IntoIterator<Item = &'k Key> {
        let dst = dst.map_or(ptr::null_mut(), |d| d.as_raw());
        let mut ptrs: Vec<_> = keys.into_iter().map(Key::as_raw).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            return_err!(ffi::gpgme_op_export_keys(
                self.as_raw(),
                keys,
                mode.bits(),
                dst,
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn clear_sender(&mut self) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_set_sender(self.as_raw(), ptr::null()));
        }
        Ok(())
    }

    #[inline]
    pub fn set_sender<S: CStrArgument>(&mut self, sender: S) -> Result<()> {
        let sender = sender.into_cstr();
        unsafe {
            return_err!(ffi::gpgme_set_sender(
                self.as_raw(),
                sender.as_ref().as_ptr(),
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn sender(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.sender_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn sender_raw(&self) -> Option<&CStr> {
        unsafe {
            ffi::gpgme_get_sender(self.as_raw())
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn clear_signers(&mut self) {
        unsafe { ffi::gpgme_signers_clear(self.as_raw()) }
    }

    #[inline]
    pub fn add_signer(&mut self, key: &Key) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_signers_add(self.as_raw(), key.as_raw()));
        }
        Ok(())
    }

    #[inline]
    pub fn signers(&self) -> Signers {
        Signers {
            ctx: self,
            current: Some(0),
        }
    }

    #[inline]
    pub fn clear_signature_notations(&mut self) {
        unsafe {
            ffi::gpgme_sig_notation_clear(self.as_raw());
        }
    }

    #[inline]
    pub fn add_signature_notation<S1, S2>(
        &mut self, name: S1, value: S2, flags: ::SignatureNotationFlags
    ) -> Result<()>
    where
        S1: CStrArgument,
        S2: CStrArgument, {
        let name = name.into_cstr();
        let value = value.into_cstr();
        unsafe {
            return_err!(ffi::gpgme_sig_notation_add(
                self.as_raw(),
                name.as_ref().as_ptr(),
                value.as_ref().as_ptr(),
                flags.bits(),
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn add_signature_policy_url<S>(&mut self, url: S, critical: bool) -> Result<()>
    where S: CStrArgument {
        let url = url.into_cstr();
        unsafe {
            let critical = if critical {
                ffi::GPGME_SIG_NOTATION_CRITICAL
            } else {
                0
            };
            return_err!(ffi::gpgme_sig_notation_add(
                self.as_raw(),
                ptr::null(),
                url.as_ref().as_ptr(),
                critical,
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn signature_policy_url(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.signature_policy_url_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn signature_policy_url_raw(&self) -> Option<&CStr> {
        unsafe {
            let mut notation = ffi::gpgme_sig_notation_get(self.as_raw());
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
    pub fn signature_notations(&self) -> SignatureNotations {
        unsafe { SignatureNotations::from_list(ffi::gpgme_sig_notation_get(self.as_raw())) }
    }

    #[inline]
    pub fn sign_clear<'p, 't, P, T>(
        &mut self, plaintext: P, signedtext: T
    ) -> Result<results::SigningResult>
    where
        P: IntoData<'p>,
        T: IntoData<'t>, {
        self.sign(SignMode::Clear, plaintext, signedtext)
    }

    #[inline]
    pub fn sign_detached<'p, 's, P, S>(
        &mut self, plaintext: P, signature: S
    ) -> Result<results::SigningResult>
    where
        P: IntoData<'p>,
        S: IntoData<'s>, {
        self.sign(SignMode::Detached, plaintext, signature)
    }

    #[inline]
    pub fn sign_normal<'p, 't, P, T>(
        &mut self, plaintext: P, signedtext: T
    ) -> Result<results::SigningResult>
    where
        P: IntoData<'p>,
        T: IntoData<'t>, {
        self.sign(SignMode::Normal, plaintext, signedtext)
    }

    #[inline]
    pub fn sign<'p, 's, P, S>(
        &mut self, mode: ::SignMode, plaintext: P, signature: S
    ) -> Result<results::SigningResult>
    where
        P: IntoData<'p>,
        S: IntoData<'s>, {
        let mut signature = signature.into_data()?;
        let mut plain = plaintext.into_data()?;
        unsafe {
            return_err!(ffi::gpgme_op_sign(
                self.as_raw(),
                plain.borrow_mut().as_raw(),
                signature.borrow_mut().as_raw(),
                mode.raw(),
            ));
        }
        Ok(self.get_result().unwrap())
    }

    #[inline]
    pub fn verify_detached<'s, 't, S, T>(
        &mut self, signature: S, signedtext: T
    ) -> Result<results::VerificationResult>
    where
        S: IntoData<'s>,
        T: IntoData<'t>, {
        let mut signature = signature.into_data()?;
        let mut signed = signedtext.into_data()?;
        self.verify(signature.borrow_mut(), Some(signed.borrow_mut()), None)
    }

    #[inline]
    pub fn verify_opaque<'s, 'p, S, P>(
        &mut self, signedtext: S, plaintext: P
    ) -> Result<results::VerificationResult>
    where
        S: IntoData<'s>,
        P: IntoData<'p>, {
        let mut signed = signedtext.into_data()?;
        let mut plain = plaintext.into_data()?;
        self.verify(signed.borrow_mut(), None, Some(plain.borrow_mut()))
    }

    fn verify(
        &mut self, signature: &mut Data, signedtext: Option<&mut Data>,
        plaintext: Option<&mut Data>,
    ) -> Result<results::VerificationResult>
    {
        unsafe {
            let signed = signedtext.map_or(ptr::null_mut(), |d| d.as_raw());
            let plain = plaintext.map_or(ptr::null_mut(), |d| d.as_raw());
            return_err!(ffi::gpgme_op_verify(
                self.as_raw(),
                signature.as_raw(),
                signed,
                plain,
            ));
        }
        Ok(self.get_result().unwrap())
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
    /// let (mut plaintext, mut ciphertext) = (Vec::new(), Vec::new());
    /// ctx.encrypt(Some(&key), &mut plaintext, &mut ciphertext).unwrap();
    /// ```
    #[inline]
    pub fn encrypt<'k, 'p, 'c, I, P, C>(
        &mut self, recp: I, plaintext: P, ciphertext: C
    ) -> Result<results::EncryptionResult>
    where
        I: IntoIterator<Item = &'k Key>,
        P: IntoData<'p>,
        C: IntoData<'c>, {
        self.encrypt_with_flags(recp, plaintext, ciphertext, ::EncryptFlags::empty())
    }

    pub fn encrypt_with_flags<'k, 'p, 'c, I, P, C>(
        &mut self, recp: I, plaintext: P, ciphertext: C, flags: ::EncryptFlags
    ) -> Result<results::EncryptionResult>
    where
        I: IntoIterator<Item = &'k Key>,
        P: IntoData<'p>,
        C: IntoData<'c>, {
        let mut plain = plaintext.into_data()?;
        let mut cipher = ciphertext.into_data()?;
        let mut ptrs: Vec<_> = recp.into_iter().map(Key::as_raw).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };

        unsafe {
            return_err!(ffi::gpgme_op_encrypt(
                self.as_raw(),
                keys,
                flags.bits(),
                plain.borrow_mut().as_raw(),
                cipher.borrow_mut().as_raw(),
            ));
        }
        Ok(self.get_result().unwrap())
    }

    #[inline]
    pub fn encrypt_symmetric<'p, 'c, P, C>(&mut self, plaintext: P, ciphertext: C) -> Result<()>
    where
        P: IntoData<'p>,
        C: IntoData<'c>, {
        self.encrypt_symmetric_with_flags(plaintext, ciphertext, ::EncryptFlags::empty())
    }

    #[inline]
    pub fn encrypt_symmetric_with_flags<'p, 'c, P, C>(
        &mut self, plaintext: P, ciphertext: C, flags: ::EncryptFlags
    ) -> Result<()>
    where
        P: IntoData<'p>,
        C: IntoData<'c>, {
        self.encrypt_with_flags(None, plaintext, ciphertext, flags)?;
        Ok(())
    }

    /// Encrypts and signs a message for the specified recipients.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use gpgme::{Context, Protocol};
    ///
    /// let mut ctx = Context::from_protocol(Protocol::OpenPgp).unwrap();
    /// let key = ctx.find_key("some pattern").unwrap();
    /// let (mut plaintext, mut ciphertext) = (Vec::new(), Vec::new());
    /// ctx.sign_and_encrypt(Some(&key), &mut plaintext, &mut ciphertext).unwrap();
    /// ```
    #[inline]
    pub fn sign_and_encrypt<'k, 'p, 'c, I, P, C>(
        &mut self, recp: I, plaintext: P, ciphertext: C
    ) -> Result<(results::EncryptionResult, results::SigningResult)>
    where
        I: IntoIterator<Item = &'k Key>,
        P: IntoData<'p>,
        C: IntoData<'c>, {
        self.sign_and_encrypt_with_flags(recp, plaintext, ciphertext, ::EncryptFlags::empty())
    }

    pub fn sign_and_encrypt_with_flags<'k, 'p, 'c, I, P, C>(
        &mut self, recp: I, plaintext: P, ciphertext: C, flags: ::EncryptFlags
    ) -> Result<(results::EncryptionResult, results::SigningResult)>
    where
        I: IntoIterator<Item = &'k Key>,
        P: IntoData<'p>,
        C: IntoData<'c>, {
        let mut plain = plaintext.into_data()?;
        let mut cipher = ciphertext.into_data()?;
        let mut ptrs: Vec<_> = recp.into_iter().map(Key::as_raw).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };

        unsafe {
            return_err!(ffi::gpgme_op_encrypt_sign(
                self.as_raw(),
                keys,
                flags.bits(),
                plain.borrow_mut().as_raw(),
                cipher.borrow_mut().as_raw(),
            ))
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
    /// let mut plain = Vec::new();
    /// ctx.decrypt(&mut cipher, &mut plain).unwrap();
    /// ```
    #[inline]
    pub fn decrypt<'c, 'p, C, P>(
        &mut self, ciphertext: C, plaintext: P
    ) -> Result<results::DecryptionResult>
    where
        C: IntoData<'c>,
        P: IntoData<'p>, {
        let mut cipher = ciphertext.into_data()?;
        let mut plain = plaintext.into_data()?;
        unsafe {
            return_err!(ffi::gpgme_op_decrypt(
                self.as_raw(),
                cipher.borrow_mut().as_raw(),
                plain.borrow_mut().as_raw(),
            ));
        }
        Ok(self.get_result().unwrap())
    }

    #[inline]
    pub fn decrypt_with_flags<'c, 'p, C, P>(
        &mut self, ciphertext: C, plaintext: P, flags: ::DecryptFlags
    ) -> Result<results::DecryptionResult>
    where
        C: IntoData<'c>,
        P: IntoData<'p>, {
        let mut cipher = ciphertext.into_data()?;
        let mut plain = plaintext.into_data()?;
        unsafe {
            return_err!(ffi::gpgme_op_decrypt_ext(
                self.as_raw(),
                flags.bits(),
                cipher.borrow_mut().as_raw(),
                plain.borrow_mut().as_raw(),
            ));
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
    /// let mut plain = Vec::new();
    /// ctx.decrypt_and_verify(&mut cipher, &mut plain).unwrap();
    /// ```
    #[inline]
    pub fn decrypt_and_verify<'c, 'p, C, P>(
        &mut self, ciphertext: C, plaintext: P
    ) -> Result<(results::DecryptionResult, results::VerificationResult)>
    where
        C: IntoData<'c>,
        P: IntoData<'p>, {
        let mut cipher = ciphertext.into_data()?;
        let mut plain = plaintext.into_data()?;
        unsafe {
            return_err!(ffi::gpgme_op_decrypt_verify(
                self.as_raw(),
                cipher.borrow_mut().as_raw(),
                plain.borrow_mut().as_raw(),
            ))
        }
        Ok((self.get_result().unwrap(), self.get_result().unwrap()))
    }

    #[inline]
    pub fn decrypt_and_verify_with_flags<'c, 'p, C, P>(
        &mut self, ciphertext: C, plaintext: P, flags: ::DecryptFlags
    ) -> Result<(results::DecryptionResult, results::VerificationResult)>
    where
        C: IntoData<'c>,
        P: IntoData<'p>, {
        self.decrypt_with_flags(ciphertext, plaintext, flags)?;
        Ok((self.get_result().unwrap(), self.get_result().unwrap()))
    }

    #[inline]
    pub fn query_swdb<S1, S2>(
        &mut self, name: Option<S1>, installed_ver: Option<S2>
    ) -> Result<results::QuerySwdbResult>
    where
        S1: CStrArgument,
        S2: CStrArgument, {
        let name = name.map(|s| s.into_cstr());
        let iversion = installed_ver.map(|s| s.into_cstr());
        unsafe {
            let name = name.as_ref().map_or(ptr::null(), |s| s.as_ref().as_ptr());
            let iversion = iversion
                .as_ref()
                .map_or(ptr::null(), |s| s.as_ref().as_ptr());
            return_err!(ffi::gpgme_op_query_swdb(self.as_raw(), name, iversion, 0));
        }
        Ok(self.get_result().unwrap())
    }

    #[inline]
    pub fn get_audit_log<'a, D>(&mut self, dst: D, flags: ::AuditLogFlags) -> Result<()>
    where D: IntoData<'a> {
        let mut dst = dst.into_data()?;
        unsafe {
            return_err!(ffi::gpgme_op_getauditlog(
                self.as_raw(),
                dst.borrow_mut().as_raw(),
                flags.bits(),
            ));
        }
        Ok(())
    }

    fn get_result<R: ::OpResult>(&self) -> Option<R> {
        R::from_context(self)
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Context")
            .field("raw", &self.as_raw())
            .field("protocol", &self.protocol())
            .field("armor", &self.armor())
            .field("text_mode", &self.text_mode())
            .field("engine", &self.engine_info())
            .finish()
    }
}

#[derive(Debug)]
pub struct Keys<'a, D = ()> {
    ctx: &'a mut Context,
    _src: Option<D>,
}

impl<'a> Keys<'a, ()> {
    fn new<I>(ctx: &mut Context, patterns: I, secret_only: bool) -> Result<Keys<()>>
    where
        I: IntoIterator,
        I::Item: CStrArgument, {
        let patterns: Vec<_> = patterns.into_iter().map(|s| s.into_cstr()).collect();
        let mut patterns: Vec<_> = patterns.iter().map(|s| s.as_ref().as_ptr()).collect();
        let ptr = if !patterns.is_empty() {
            patterns.push(ptr::null());
            patterns.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            return_err!(ffi::gpgme_op_keylist_ext_start(
                ctx.as_raw(),
                ptr,
                if secret_only { 1 } else { 0 },
                0,
            ));
        }
        Ok(Keys {
            ctx: ctx,
            _src: None,
        })
    }

    #[inline]
    pub fn from_data<'d, D>(ctx: &mut Context, src: D) -> Result<Keys<D::Output>>
    where D: IntoData<'d> {
        let mut src = src.into_data()?;
        unsafe {
            return_err!(ffi::gpgme_op_keylist_from_data_start(
                ctx.as_raw(),
                src.borrow_mut().as_raw(),
                0,
            ));
        }
        Ok(Keys {
            ctx: ctx,
            _src: Some(src),
        })
    }
}

impl<'a, D> Keys<'a, D> {
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

impl<'a, D> Drop for Keys<'a, D> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_op_keylist_end(self.ctx.as_raw());
        }
    }
}

impl<'a, D> Iterator for Keys<'a, D> {
    type Item = Result<Key>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let mut key = ptr::null_mut();
            match Error::new(ffi::gpgme_op_keylist_next(self.ctx.as_raw(), &mut key)) {
                Error::NO_ERROR => Some(Ok(Key::from_raw(key))),
                e if e.code() == Error::EOF.code() => None,
                e => Some(Err(e)),
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
            match Error::new(ffi::gpgme_op_trustlist_next(
                self.ctx.as_raw(),
                &mut trust_item,
            )) {
                Error::NO_ERROR => Some(Ok(TrustItem::from_raw(trust_item))),
                e if e.code() == Error::EOF.code() => None,
                e => Some(Err(e)),
            }
        }
    }
}

#[derive(Clone)]
pub struct Signers<'a> {
    ctx: &'a Context,
    current: Option<libc::c_int>,
}

impl<'a> Iterator for Signers<'a> {
    type Item = Key;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            self.current.and_then(|x| {
                match ffi::gpgme_signers_enum(self.ctx.as_raw(), x).as_mut() {
                    Some(key) => {
                        self.current = x.checked_add(1);
                        Some(Key::from_raw(key))
                    }
                    _ => {
                        self.current = None;
                        None
                    }
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

    require_gpgme_ver! {
        (1, 5) => {
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
    }
}

impl<'a> fmt::Debug for Signers<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}
