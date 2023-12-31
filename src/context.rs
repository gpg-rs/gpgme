use std::{
    borrow::BorrowMut,
    ffi::CStr,
    fmt,
    iter::FusedIterator,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
    ptr,
    str::Utf8Error,
    time::Duration,
};

use conv::{UnwrapOrSaturate, ValueInto};
use ffi;
use libc;

#[allow(deprecated)]
use crate::{
    callbacks, edit,
    engine::{EngineInfo, EngineInfos},
    notation::SignatureNotations,
    results,
    utils::{convert_err, CStrArgument, SmallVec},
    Data, EditInteractor, Error, ExportMode, Interactor, IntoData, Key, KeyListMode, NonNull,
    PassphraseProvider, ProgressReporter, Protocol, Result, SignMode, StatusHandler,
};

/// A context for cryptographic operations.
///
/// Upstream documentation:
/// [`gpgme_ctx_t`](https://www.gnupg.org/documentation/manuals/gpgme/Contexts.html#Contexts)
#[must_use]
pub struct Context(NonNull<ffi::gpgme_ctx_t>);

impl Drop for Context {
    #[inline]
    fn drop(&mut self) {
        unsafe { ffi::gpgme_release(self.as_raw()) }
    }
}

impl Context {
    impl_wrapper!(ffi::gpgme_ctx_t);

    pub(crate) fn new() -> Result<Self> {
        crate::init();
        unsafe {
            let mut ctx = ptr::null_mut();
            convert_err(ffi::gpgme_new(&mut ctx))?;
            Ok(Context::from_raw(ctx))
        }
    }

    /// Creates a new context and initializes it to work with the specified protocol.
    ///
    /// Upstream documentation: [`gpgme_new`] and [`gpgme_set_protocol`]
    ///
    /// [`gpgme_new`]: https://www.gnupg.org/documentation/manuals/gpgme/Creating-Contexts.html#Creating-Contexts
    /// [`gpgme_set_protocol`]: https://www.gnupg.org/documentation/manuals/gpgme/Protocol-Selection.html#index-gpgme_005fset_005fprotocol
    #[inline]
    pub fn from_protocol(proto: Protocol) -> Result<Self> {
        let ctx = Context::new()?;
        unsafe {
            convert_err(ffi::gpgme_set_protocol(ctx.as_raw(), proto.raw()))?;
        }
        Ok(ctx)
    }

    /// Upstream documentation:
    /// [`gpgme_get_protocol`](https://www.gnupg.org/documentation/manuals/gpgme/Protocol-Selection.html#index-gpgme_005fget_005fprotocol)
    #[inline]
    pub fn protocol(&self) -> Protocol {
        unsafe { Protocol::from_raw(ffi::gpgme_get_protocol(self.as_raw())) }
    }

    /// Upstream documentation:
    /// [`gpgme_get_armor`](https://www.gnupg.org/documentation/manuals/gpgme/ASCII-Armor.html#index-gpgme_005fget_005farmor)
    #[inline]
    pub fn armor(&self) -> bool {
        unsafe { ffi::gpgme_get_armor(self.as_raw()) != 0 }
    }

    /// Upstream documentation:
    /// [`gpgme_set_armor`](https://www.gnupg.org/documentation/manuals/gpgme/ASCII-Armor.html#index-gpgme_005fset_005farmor)
    #[inline]
    pub fn set_armor(&mut self, enabled: bool) {
        unsafe {
            ffi::gpgme_set_armor(self.as_raw(), if enabled { 1 } else { 0 });
        }
    }

    /// Upstream documentation:
    /// [`gpgme_get_textmode`](https://www.gnupg.org/documentation/manuals/gpgme/Text-Mode.html#index-gpgme_005fget_005ftextmode)
    #[inline]
    pub fn text_mode(&self) -> bool {
        unsafe { ffi::gpgme_get_textmode(self.as_raw()) != 0 }
    }

    /// Upstream documentation:
    /// [`gpgme_set_textmode`](https://www.gnupg.org/documentation/manuals/gpgme/Text-Mode.html#index-gpgme_005fset_005ftextmode)
    #[inline]
    pub fn set_text_mode(&mut self, enabled: bool) {
        unsafe {
            ffi::gpgme_set_textmode(self.as_raw(), if enabled { 1 } else { 0 });
        }
    }

    /// Upstream documentation:
    /// [`gpgme_get_offline`](https://www.gnupg.org/documentation/manuals/gpgme/Offline-Mode.html#index-gpgme_005fget_005foffline)
    #[inline]
    pub fn offline(&self) -> bool {
        unsafe { ffi::gpgme_get_offline(self.as_raw()) != 0 }
    }

    /// Upstream documentation:
    /// [`gpgme_set_offline`](https://www.gnupg.org/documentation/manuals/gpgme/Offline-Mode.html#index-gpgme_005fset_005foffline)
    #[inline]
    pub fn set_offline(&mut self, enabled: bool) {
        unsafe {
            ffi::gpgme_set_offline(self.as_raw(), if enabled { 1 } else { 0 });
        }
    }

    /// Upstream documentation:
    /// [`gpgme_get_ctx_flag`](https://www.gnupg.org/documentation/manuals/gpgme/Context-Flags.html#index-gpgme_005fget_005fctx_005fflag)
    #[inline]
    pub fn get_flag(&self, name: impl CStrArgument) -> Result<&str, Option<Utf8Error>> {
        self.get_flag_raw(name)
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    /// Upstream documentation:
    /// [`gpgme_get_ctx_flag`](https://www.gnupg.org/documentation/manuals/gpgme/Context-Flags.html#index-gpgme_005fget_005fctx_005fflag)
    #[inline]
    pub fn get_flag_raw(&self, name: impl CStrArgument) -> Option<&CStr> {
        let name = name.into_cstr();
        unsafe {
            ffi::gpgme_get_ctx_flag(self.as_raw(), name.as_ref().as_ptr())
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_set_ctx_flag`](https://www.gnupg.org/documentation/manuals/gpgme/Context-Flags.html#index-gpgme_005fset_005fctx_005fflag)
    #[inline]
    pub fn set_flag(&mut self, name: impl CStrArgument, value: impl CStrArgument) -> Result<()> {
        let name = name.into_cstr();
        let value = value.into_cstr();
        unsafe {
            convert_err(ffi::gpgme_set_ctx_flag(
                self.as_raw(),
                name.as_ref().as_ptr(),
                value.as_ref().as_ptr(),
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_ctx_get_engine_info`](https://www.gnupg.org/documentation/manuals/gpgme/Crypto-Engine.html#index-gpgme_005fctx_005fget_005fengine_005finfo)
    #[inline]
    pub fn engine_info(&self) -> EngineInfo<'_> {
        unsafe { EngineInfo::from_raw(ffi::gpgme_ctx_get_engine_info(self.as_raw())) }
    }

    /// Upstream documentation:
    /// [`gpgme_ctx_get_engine_info`](https://www.gnupg.org/documentation/manuals/gpgme/Crypto-Engine.html#index-gpgme_005fctx_005fget_005fengine_005finfo)
    #[inline]
    pub fn engines(&self) -> EngineInfos<'_> {
        unsafe { EngineInfos::from_list(ffi::gpgme_ctx_get_engine_info(self.as_raw())) }
    }

    #[inline]
    pub fn set_engine_path(&mut self, path: impl CStrArgument) -> Result<()> {
        let path = path.into_cstr();
        let home_dir = self
            .engine_info()
            .home_dir_raw()
            .map_or(ptr::null(), CStr::as_ptr);
        unsafe {
            convert_err(ffi::gpgme_ctx_set_engine_info(
                self.as_raw(),
                self.protocol().raw(),
                path.as_ref().as_ptr(),
                home_dir,
            ))
        }
    }

    #[inline]
    pub fn set_engine_home_dir(&mut self, home_dir: impl CStrArgument) -> Result<()> {
        let path = self
            .engine_info()
            .path_raw()
            .map_or(ptr::null(), CStr::as_ptr);
        let home_dir = home_dir.into_cstr();
        unsafe {
            convert_err(ffi::gpgme_ctx_set_engine_info(
                self.as_raw(),
                self.protocol().raw(),
                path,
                home_dir.as_ref().as_ptr(),
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_ctx_set_engine_info`](https://www.gnupg.org/documentation/manuals/gpgme/Crypto-Engine.html#index-gpgme_005fctx_005fset_005fengine_005finfo)
    #[inline]
    pub fn set_engine_info(
        &mut self,
        path: Option<impl CStrArgument>,
        home_dir: Option<impl CStrArgument>,
    ) -> Result<()> {
        let path = path.map(CStrArgument::into_cstr);
        let home_dir = home_dir.map(CStrArgument::into_cstr);
        unsafe {
            let path = path.as_ref().map_or(ptr::null(), |s| s.as_ref().as_ptr());
            let home_dir = home_dir
                .as_ref()
                .map_or(ptr::null(), |s| s.as_ref().as_ptr());
            convert_err(ffi::gpgme_ctx_set_engine_info(
                self.as_raw(),
                self.protocol().raw(),
                path,
                home_dir,
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_get_pinentry_mode`](https://www.gnupg.org/documentation/manuals/gpgme/Pinentry-Mode.html#index-gpgme_005fget_005fpinentry_005fmode)
    #[inline]
    pub fn pinentry_mode(&self) -> crate::PinentryMode {
        unsafe { crate::PinentryMode::from_raw(ffi::gpgme_get_pinentry_mode(self.as_raw())) }
    }

    /// Upstream documentation:
    /// [`gpgme_set_pinentry_mode`](https://www.gnupg.org/documentation/manuals/gpgme/Pinentry-Mode.html#index-gpgme_005fset_005fpinentry_005fmode)
    #[inline]
    pub fn set_pinentry_mode(&mut self, mode: crate::PinentryMode) -> Result<()> {
        if (mode != crate::PinentryMode::Default)
            && (self.protocol() == Protocol::OpenPgp)
            && !self.engine_info().check_version("2.1")
        {
            return Err(Error::NOT_SUPPORTED);
        }
        unsafe { convert_err(ffi::gpgme_set_pinentry_mode(self.as_raw(), mode.raw())) }
    }

    /// Upstream documentation:
    /// [`gpgme_set_passphrase_cb`](https://www.gnupg.org/documentation/manuals/gpgme/Passphrase-Callback.html#index-gpgme_005fset_005fpassphrase_005fcb)
    #[inline]
    pub fn clear_passphrase_provider(&mut self) {
        unsafe {
            ffi::gpgme_set_passphrase_cb(self.as_raw(), None, ptr::null_mut());
        }
    }

    /// Upstream documentation:
    /// [`gpgme_set_passphrase_cb`](https://www.gnupg.org/documentation/manuals/gpgme/Passphrase-Callback.html#index-gpgme_005fset_005fpassphrase_005fcb)
    #[inline]
    pub fn set_passphrase_provider<'a, P>(self, provider: P) -> ContextWithCallbacks<'a>
    where
        P: PassphraseProvider + 'a,
    {
        let mut wrapper = ContextWithCallbacks::from(self);
        wrapper.set_passphrase_provider(provider);
        wrapper
    }

    /// Uses the specified provider to handle passphrase requests for the duration of the
    /// closure.
    ///
    /// Upstream documentation:
    /// [`gpgme_set_passphrase_cb`](https://www.gnupg.org/documentation/manuals/gpgme/Passphrase-Callback.html#index-gpgme_005fset_005fpassphrase_005fcb)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io::prelude::*;
    ///
    /// use gpgme::{Context, PassphraseRequest, Protocol};
    ///
    /// let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
    /// ctx.with_passphrase_provider(|_: PassphraseRequest, out: &mut dyn Write| {
    ///     out.write_all(b"some passphrase")?;
    ///     Ok(())
    /// }, |mut ctx| {
    ///     // Do something with ctx requiring a passphrase, for example decryption
    /// });
    /// # Ok::<(), gpgme::Error>(())
    /// ```
    pub fn with_passphrase_provider<R, P>(
        &mut self,
        provider: P,
        f: impl FnOnce(&mut Context) -> R,
    ) -> R
    where
        P: PassphraseProvider,
    {
        unsafe {
            let mut old = (None, ptr::null_mut());
            ffi::gpgme_get_passphrase_cb(self.as_raw(), &mut old.0, &mut old.1);
            let mut hook = callbacks::Hook::from(provider);
            let _guard = callbacks::PassphraseCbGuard {
                ctx: self.as_raw(),
                old,
            };
            ffi::gpgme_set_passphrase_cb(
                self.as_raw(),
                Some(callbacks::passphrase_cb::<P>),
                ptr::addr_of_mut!(hook).cast(),
            );
            f(self)
        }
    }

    /// Upstream documentation:
    /// [`gpgme_set_progress_cb`](https://www.gnupg.org/documentation/manuals/gpgme/Progress-Meter-Callback.html#index-gpgme_005fset_005fprogress_005fcb)
    #[inline]
    pub fn clear_progress_reporter(&mut self) {
        unsafe {
            ffi::gpgme_set_progress_cb(self.as_raw(), None, ptr::null_mut());
        }
    }

    /// Upstream documentation:
    /// [`gpgme_set_progress_cb`](https://www.gnupg.org/documentation/manuals/gpgme/Progress-Meter-Callback.html#index-gpgme_005fset_005fprogress_005fcb)
    #[inline]
    pub fn set_progress_reporter<'a, P>(self, reporter: P) -> ContextWithCallbacks<'a>
    where
        P: ProgressReporter + 'a,
    {
        let mut wrapper = ContextWithCallbacks::from(self);
        wrapper.set_progress_reporter(reporter);
        wrapper
    }

    /// Upstream documentation:
    /// [`gpgme_set_progress_cb`](https://www.gnupg.org/documentation/manuals/gpgme/Progress-Meter-Callback.html#index-gpgme_005fset_005fprogress_005fcb)
    pub fn with_progress_reporter<R, H>(
        &mut self,
        handler: H,
        f: impl FnOnce(&mut Context) -> R,
    ) -> R
    where
        H: ProgressReporter,
    {
        unsafe {
            let mut old = (None, ptr::null_mut());
            ffi::gpgme_get_progress_cb(self.as_raw(), &mut old.0, &mut old.1);
            let mut hook = callbacks::Hook::from(handler);
            let _guard = callbacks::ProgressCbGuard {
                ctx: self.as_raw(),
                old,
            };
            ffi::gpgme_set_progress_cb(
                self.as_raw(),
                Some(callbacks::progress_cb::<H>),
                ptr::addr_of_mut!(hook).cast(),
            );
            f(self)
        }
    }

    /// Upstream documentation:
    /// [`gpgme_set_status_cb`](https://www.gnupg.org/documentation/manuals/gpgme/Status-Message-Callback.html#index-gpgme_005fset_005fstatus_005fcb)
    pub fn clear_status_handler(&mut self) {
        unsafe {
            ffi::gpgme_set_status_cb(self.as_raw(), None, ptr::null_mut());
        }
    }

    /// Upstream documentation:
    /// [`gpgme_set_status_cb`](https://www.gnupg.org/documentation/manuals/gpgme/Status-Message-Callback.html#index-gpgme_005fset_005fstatus_005fcb)
    #[inline]
    pub fn set_status_handler<'a, H>(self, handler: H) -> ContextWithCallbacks<'a>
    where
        H: StatusHandler + 'a,
    {
        let mut wrapper = ContextWithCallbacks::from(self);
        wrapper.set_status_handler(handler);
        wrapper
    }

    /// Upstream documentation:
    /// [`gpgme_set_status_cb`](https://www.gnupg.org/documentation/manuals/gpgme/Status-Message-Callback.html#index-gpgme_005fset_005fstatus_005fcb)
    pub fn with_status_handler<R, H>(&mut self, handler: H, f: impl FnOnce(&mut Context) -> R) -> R
    where
        H: StatusHandler,
    {
        unsafe {
            let mut old = (None, ptr::null_mut());
            ffi::gpgme_get_status_cb(self.as_raw(), &mut old.0, &mut old.1);
            let mut hook = callbacks::Hook::from(handler);
            let _guard = callbacks::StatusCbGuard {
                ctx: self.as_raw(),
                old,
            };
            ffi::gpgme_set_status_cb(
                self.as_raw(),
                Some(callbacks::status_cb::<H>),
                ptr::addr_of_mut!(hook).cast(),
            );
            f(self)
        }
    }

    /// Upstream documentation:
    /// [`gpgme_get_keylist_mode`](https://www.gnupg.org/documentation/manuals/gpgme/Key-Listing-Mode.html#index-gpgme_005fget_005fkeylist_005fmode)
    #[inline]
    pub fn key_list_mode(&self) -> KeyListMode {
        unsafe { KeyListMode::from_bits_retain(ffi::gpgme_get_keylist_mode(self.as_raw())) }
    }

    /// Adds all flags set in the provided key listing mode to the `Context`'s current mode.
    ///
    /// Upstream documentation:
    /// [`gpgme_set_keylist_mode`](https://www.gnupg.org/documentation/manuals/gpgme/Key-Listing-Mode.html#index-gpgme_005fset_005fkeylist_005fmode)
    #[inline]
    pub fn add_key_list_mode(&mut self, mask: KeyListMode) -> Result<()> {
        unsafe {
            let old = ffi::gpgme_get_keylist_mode(self.as_raw());
            convert_err(ffi::gpgme_set_keylist_mode(
                self.as_raw(),
                mask.bits() | old,
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_set_keylist_mode`](https://www.gnupg.org/documentation/manuals/gpgme/Key-Listing-Mode.html#index-gpgme_005fset_005fkeylist_005fmode)
    #[inline]
    pub fn set_key_list_mode(&mut self, mode: KeyListMode) -> Result<()> {
        unsafe { convert_err(ffi::gpgme_set_keylist_mode(self.as_raw(), mode.bits())) }
    }

    /// Returns an iterator over all public keys available in the keyring.
    #[inline]
    pub fn keys(&mut self) -> Result<Keys<'_>> {
        self.find_keys(None::<String>)
    }

    /// Returns an iterator over all secret keys available in the keyring.
    #[inline]
    pub fn secret_keys(&mut self) -> Result<Keys<'_>> {
        self.find_secret_keys(None::<String>)
    }

    /// Returns an updated version of the provided key.
    #[inline]
    pub fn refresh_key(&mut self, key: &Key) -> Result<Key> {
        let fpr = key.fingerprint_raw().ok_or(Error::AMBIGUOUS_NAME)?;
        if key.has_secret() {
            if let r @ Ok(_) = self.get_secret_key(fpr) {
                return r;
            }
        }
        self.get_key(fpr)
    }

    /// Returns the public key with the specified fingerprint, if such a key can
    /// be found. Otherwise, an error is returned.
    ///
    /// Upstream documentation:
    /// [`gpgme_get_key`](https://www.gnupg.org/documentation/manuals/gpgme/Listing-Keys.html#index-gpgme_005fget_005fkey)
    #[inline]
    pub fn get_key(&mut self, fpr: impl CStrArgument) -> Result<Key> {
        let fingerprint = fpr.into_cstr();
        unsafe {
            let mut key = ptr::null_mut();
            convert_err(ffi::gpgme_get_key(
                self.as_raw(),
                fingerprint.as_ref().as_ptr(),
                &mut key,
                0,
            ))?;
            Ok(Key::from_raw(key))
        }
    }

    /// Returns the secret key with the specified fingerprint, if such a key can
    /// be found. Otherwise, an error is returned.
    ///
    /// Upstream documentation:
    /// [`gpgme_get_key`](https://www.gnupg.org/documentation/manuals/gpgme/Listing-Keys.html#index-gpgme_005fget_005fkey)
    #[inline]
    pub fn get_secret_key(&mut self, fpr: impl CStrArgument) -> Result<Key> {
        let fingerprint = fpr.into_cstr();
        unsafe {
            let mut key = ptr::null_mut();
            convert_err(ffi::gpgme_get_key(
                self.as_raw(),
                fingerprint.as_ref().as_ptr(),
                &mut key,
                1,
            ))?;
            Ok(Key::from_raw(key))
        }
    }

    #[inline]
    pub fn locate_key(&mut self, email: impl CStrArgument) -> Result<Key> {
        self.add_key_list_mode(KeyListMode::LOCATE)?;
        self.find_keys(Some(email))?
            .next()
            .unwrap_or(Err(Error::NOT_FOUND))
    }

    /// Returns an iterator over a list of all public keys matching one or more of the
    /// specified patterns.
    ///
    /// Upstream documentation:
    /// [`gpgme_op_keylist_ext_start`](https://www.gnupg.org/documentation/manuals/gpgme/Listing-Keys.html#index-gpgme_005fop_005fkeylist_005fext_005fstart)
    #[inline]
    pub fn find_keys<I>(&mut self, patterns: I) -> Result<Keys<'_>>
    where
        I: IntoIterator,
        I::Item: CStrArgument,
    {
        self.search_keys(patterns, false)
    }

    /// Returns an iterator over a list of all secret keys matching one or more of the
    /// specified patterns.
    ///
    /// Upstream documentation:
    /// [`gpgme_op_keylist_ext_start`](https://www.gnupg.org/documentation/manuals/gpgme/Listing-Keys.html#index-gpgme_005fop_005fkeylist_005fext_005fstart)
    #[inline]
    pub fn find_secret_keys<I>(&mut self, patterns: I) -> Result<Keys<'_>>
    where
        I: IntoIterator,
        I::Item: CStrArgument,
    {
        self.search_keys(patterns, true)
    }

    fn search_keys<I>(&mut self, patterns: I, secret_only: bool) -> Result<Keys<'_>>
    where
        I: IntoIterator,
        I::Item: CStrArgument,
    {
        let patterns: SmallVec<_> = patterns.into_iter().map(|s| s.into_cstr()).collect();
        let mut patterns: SmallVec<_> = patterns.iter().map(|s| s.as_ref().as_ptr()).collect();
        let ptr = if !patterns.is_empty() {
            patterns.push(ptr::null());
            patterns.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            convert_err(ffi::gpgme_op_keylist_ext_start(
                self.as_raw(),
                ptr,
                if secret_only { 1 } else { 0 },
                0,
            ))?;
        }
        Ok(Keys {
            ctx: self,
            _src: (),
        })
    }

    /// Returns an iterator over the keys encoded in the specified source.
    ///
    /// Upstream documentation:
    /// [`gpgme_op_keylist_from_data_start`](https://www.gnupg.org/documentation/manuals/gpgme/Listing-Keys.html#index-gpgme_005fop_005fkeylist_005ffrom_005fdata_005fstart)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use gpgme::{Context, Data, Protocol};
    ///
    /// let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
    /// let mut keyring = Data::load("somefile")?;
    /// for key in ctx.read_keys(&mut keyring)? {
    ///     println!("{:?}", key);
    /// }
    /// # Ok::<(), gpgme::Error>(())
    /// ```
    #[inline]
    pub fn read_keys<'s, 'd, D>(&'s mut self, src: D) -> Result<Keys<'d, D::Output>>
    where
        D: IntoData<'d>,
        's: 'd,
    {
        Keys::from_data(self, src)
    }

    /// Upstream documentation:
    /// [`gpgme_op_genkey`](https://www.gnupg.org/documentation/manuals/gpgme/Generating-Keys.html#index-gpgme_005fop_005fgenkey)
    #[inline]
    pub fn generate_key<'d1, 'd2, D1, D2>(
        &mut self,
        params: impl CStrArgument,
        public: Option<D1>,
        secret: Option<D2>,
    ) -> Result<results::KeyGenerationResult>
    where
        D1: IntoData<'d1>,
        D2: IntoData<'d2>,
    {
        let params = params.into_cstr();
        let mut public = public.map_or(Ok(None), |d| d.into_data().map(Some))?;
        let mut secret = secret.map_or(Ok(None), |d| d.into_data().map(Some))?;
        unsafe {
            convert_err(ffi::gpgme_op_genkey(
                self.as_raw(),
                params.as_ref().as_ptr(),
                public
                    .as_mut()
                    .map_or(ptr::null_mut(), |d| d.borrow_mut().as_raw()),
                secret
                    .as_mut()
                    .map_or(ptr::null_mut(), |d| d.borrow_mut().as_raw()),
            ))?;
        }
        Ok(self.get_result().unwrap())
    }

    /// Creates a new OpenPGP key.
    ///
    /// Upstream documentation:
    /// [`gpgme_op_createkey`](https://www.gnupg.org/documentation/manuals/gpgme/Generating-Keys.html#index-gpgme_005fop_005fcreatekey)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use gpgme::{Context, Data, Protocol};
    ///
    /// let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
    /// let result = ctx.create_key("Example User <example@example.com>", "default", Default::default())?;
    /// println!("Key Fingerprint: {}", result.fingerprint().unwrap());
    /// # Ok::<(), gpgme::Error>(())
    /// ```
    #[inline]
    pub fn create_key(
        &mut self,
        userid: impl CStrArgument,
        algo: impl CStrArgument,
        expires: Duration,
    ) -> Result<results::KeyGenerationResult> {
        self.create_key_with_flags(userid, algo, expires, crate::CreateKeyFlags::empty())
    }

    /// Upstream documentation:
    /// [`gpgme_op_createkey`](https://www.gnupg.org/documentation/manuals/gpgme/Generating-Keys.html#index-gpgme_005fop_005fcreatekey)
    #[inline]
    pub fn create_key_with_flags(
        &mut self,
        userid: impl CStrArgument,
        algo: impl CStrArgument,
        expires: Duration,
        flags: crate::CreateKeyFlags,
    ) -> Result<results::KeyGenerationResult> {
        let userid = userid.into_cstr();
        let algo = algo.into_cstr();
        let expires = expires.as_secs().value_into().unwrap_or_saturate();
        unsafe {
            convert_err(ffi::gpgme_op_createkey(
                self.as_raw(),
                userid.as_ref().as_ptr(),
                algo.as_ref().as_ptr(),
                0,
                expires,
                ptr::null_mut(),
                flags.bits(),
            ))?;
        }
        Ok(self.get_result().unwrap())
    }

    /// Upstream documentation:
    /// [`gpgme_op_createsubkey`](https://www.gnupg.org/documentation/manuals/gpgme/Generating-Keys.html#index-gpgme_005fop_005fcreatesubkey)
    #[inline]
    pub fn create_subkey(
        &mut self,
        key: &Key,
        algo: impl CStrArgument,
        expires: Duration,
    ) -> Result<results::KeyGenerationResult> {
        self.create_subkey_with_flags(key, algo, expires, crate::CreateKeyFlags::empty())
    }

    /// Upstream documentation:
    /// [`gpgme_op_createsubkey`](https://www.gnupg.org/documentation/manuals/gpgme/Generating-Keys.html#index-gpgme_005fop_005fcreatesubkey)
    #[inline]
    pub fn create_subkey_with_flags(
        &mut self,
        key: &Key,
        algo: impl CStrArgument,
        expires: Duration,
        flags: crate::CreateKeyFlags,
    ) -> Result<results::KeyGenerationResult> {
        let algo = algo.into_cstr();
        let expires = expires.as_secs().value_into().unwrap_or_saturate();
        unsafe {
            convert_err(ffi::gpgme_op_createsubkey(
                self.as_raw(),
                key.as_raw(),
                algo.as_ref().as_ptr(),
                0,
                expires,
                flags.bits(),
            ))?;
        }
        Ok(self.get_result().unwrap())
    }

    /// Upstream documentation:
    /// [`gpgme_op_setexpire`](https://www.gnupg.org/documentation/manuals/gpgme/Manipulating-Keys.html#index-gpgme_005fop_005fsetexpire)
    #[cfg(feature = "v1_15")]
    pub fn set_expire_all(&mut self, key: &Key, expires: Duration) -> Result<()> {
        let expires = expires.as_secs().value_into().unwrap_or_saturate();
        unsafe {
            convert_err(ffi::gpgme_op_setexpire(
                self.as_raw(),
                key.as_raw(),
                expires,
                b"*\0".into_cstr().as_ref().as_ptr(),
                0,
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_op_setexpire`](https://www.gnupg.org/documentation/manuals/gpgme/Manipulating-Keys.html#index-gpgme_005fop_005fsetexpire)
    #[cfg(feature = "v1_15")]
    pub fn set_expire<I>(&mut self, key: &Key, expires: Duration, subkeys: I) -> Result<()>
    where
        I: IntoIterator,
        I::Item: CStrArgument,
    {
        let expires = expires.as_secs().value_into().unwrap_or_saturate();
        self::with_joined_cstr(subkeys, |subkeys, _| unsafe {
            convert_err(ffi::gpgme_op_setexpire(
                self.as_raw(),
                key.as_raw(),
                expires,
                subkeys.map_or(ptr::null(), |subkeys| subkeys.as_ptr()),
                0,
            ))
        })
    }

    /// Upstream documentation:
    /// [`gpgme_op_adduid`](https://www.gnupg.org/documentation/manuals/gpgme/Generating-Keys.html#index-gpgme_005fop_005fadduid)
    #[inline]
    pub fn add_uid(&mut self, key: &Key, userid: impl CStrArgument) -> Result<()> {
        let userid = userid.into_cstr();
        unsafe {
            convert_err(ffi::gpgme_op_adduid(
                self.as_raw(),
                key.as_raw(),
                userid.as_ref().as_ptr(),
                0,
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_op_revuid`](https://www.gnupg.org/documentation/manuals/gpgme/Generating-Keys.html#index-gpgme_005fop_005frevuid)
    #[inline]
    pub fn revoke_uid(&mut self, key: &Key, userid: impl CStrArgument) -> Result<()> {
        let userid = userid.into_cstr();
        unsafe {
            convert_err(ffi::gpgme_op_revuid(
                self.as_raw(),
                key.as_raw(),
                userid.as_ref().as_ptr(),
                0,
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_op_set_uid_flag`](https://www.gnupg.org/documentation/manuals/gpgme/Generating-Keys.html#index-gpgme_005fop_005fset_005fui_005fflag)
    #[inline]
    pub fn set_uid_flag(
        &mut self,
        key: &Key,
        userid: impl CStrArgument,
        name: impl CStrArgument,
        value: Option<impl CStrArgument>,
    ) -> Result<()> {
        let userid = userid.into_cstr();
        let name = name.into_cstr();
        let value = value.map(CStrArgument::into_cstr);
        unsafe {
            convert_err(ffi::gpgme_op_set_uid_flag(
                self.as_raw(),
                key.as_raw(),
                userid.as_ref().as_ptr(),
                name.as_ref().as_ptr(),
                value.as_ref().map_or(ptr::null(), |s| s.as_ref().as_ptr()),
            ))
        }
    }

    #[inline]
    pub fn set_primary_uid(&mut self, key: &Key, userid: impl CStrArgument) -> Result<()> {
        self.set_uid_flag(key, userid, "primary\0", None::<String>)
    }

    /// Signs the given key with the default signing key, or the keys specified via
    /// [`Context::add_signer()`].
    ///
    /// Upstream documentation:
    /// [`gpgme_op_keysign`](https://www.gnupg.org/documentation/manuals/gpgme/Signing-Keys.html#index-gpgme_005fop_005fkeysign)
    #[inline]
    pub fn sign_key<I>(&mut self, key: &Key, userids: I, expires: Duration) -> Result<()>
    where
        I: IntoIterator,
        I::Item: CStrArgument,
    {
        self.sign_key_with_flags(key, userids, expires, crate::KeySigningFlags::empty())
    }

    /// Signs the given key with the default signing key, or the keys specified via
    /// [`Context::add_signer()`].
    ///
    /// Upstream documentation:
    /// [`gpgme_op_keysign`](https://www.gnupg.org/documentation/manuals/gpgme/Signing-Keys.html#index-gpgme_005fop_005fkeysign)
    pub fn sign_key_with_flags<I>(
        &mut self,
        key: &Key,
        userids: I,
        expires: Duration,
        mut flags: crate::KeySigningFlags,
    ) -> Result<()>
    where
        I: IntoIterator,
        I::Item: CStrArgument,
    {
        let expires = expires.as_secs().value_into().unwrap_or_saturate();
        self::with_joined_cstr(userids, |userids, count| {
            if count > 1 {
                flags |= crate::KeySigningFlags::LFSEP;
            }
            unsafe {
                convert_err(ffi::gpgme_op_keysign(
                    self.as_raw(),
                    key.as_raw(),
                    userids.map_or(ptr::null(), |uid| uid.as_ptr()),
                    expires,
                    flags.bits(),
                ))
            }
        })
    }

    /// Upstream documentation:
    /// [`gpgme_op_revsig`](https://www.gnupg.org/documentation/manuals/gpgme/Signing-Keys.html#index-gpgme_005fop_005frevsig)
    #[inline]
    #[cfg(feature = "v1_15")]
    pub fn revoke_signature<I>(&mut self, key: &Key, signing_key: &Key, userids: I) -> Result<()>
    where
        I: IntoIterator,
        I::Item: CStrArgument,
    {
        self::with_joined_cstr(userids, |userids, count| {
            let flags = if count > 1 {
                ffi::GPGME_REVSIG_LFSEP
            } else {
                0
            };
            unsafe {
                convert_err(ffi::gpgme_op_revsig(
                    self.as_raw(),
                    key.as_raw(),
                    signing_key.as_raw(),
                    userids.map_or(ptr::null(), |uid| uid.as_ptr()),
                    flags,
                ))
            }
        })
    }

    /// Upstream documentation:
    /// [`gpgme_op_tofu_policy`](https://www.gnupg.org/documentation/manuals/gpgme/Changing-TOFU-Data.html#index-gpgme_005fop_005ftofu_005fpolicy)
    #[inline]
    pub fn change_key_tofu_policy(&mut self, key: &Key, policy: crate::TofuPolicy) -> Result<()> {
        unsafe {
            convert_err(ffi::gpgme_op_tofu_policy(
                self.as_raw(),
                key.as_raw(),
                policy.raw(),
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_op_passwd`](https://www.gnupg.org/documentation/manuals/gpgme/Changing-Passphrases.html#index-gpgme_005fop_005fpasswd)
    #[inline]
    pub fn change_key_passphrase(&mut self, key: &Key) -> Result<()> {
        unsafe { convert_err(ffi::gpgme_op_passwd(self.as_raw(), key.as_raw(), 0)) }
    }

    /// Upstream documentation:
    /// [`gpgme_op_edit`](https://www.gnupg.org/documentation/manuals/gpgme/Deprecated-Functions.html#index-gpgme_005fop_005fedit)
    #[inline]
    #[allow(deprecated)]
    #[deprecated(since = "0.9.2", note = "use `interact` instead")]
    pub fn edit_key<'a, E, D>(&mut self, key: &Key, interactor: E, data: D) -> Result<()>
    where
        E: EditInteractor,
        D: IntoData<'a>,
    {
        let mut data = data.into_data()?;
        let mut hook = callbacks::InteractorHook {
            inner: interactor.into(),
            response: data.borrow_mut(),
        };
        unsafe {
            convert_err(ffi::gpgme_op_edit(
                self.as_raw(),
                key.as_raw(),
                Some(callbacks::edit_cb::<E>),
                ptr::addr_of_mut!(hook).cast(),
                (*hook.response).as_raw(),
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_op_card_edit`](https://www.gnupg.org/documentation/manuals/gpgme/Deprecated-Functions.html#index-gpgme_005fop_005fcard_005fedit)
    #[inline]
    #[allow(deprecated)]
    #[deprecated(since = "0.9.2", note = "use `interact_with_card` instead")]
    pub fn edit_card_key<'a, E, D>(&mut self, key: &Key, interactor: E, data: D) -> Result<()>
    where
        E: EditInteractor,
        D: IntoData<'a>,
    {
        let mut data = data.into_data()?;
        let mut hook = callbacks::InteractorHook {
            inner: interactor.into(),
            response: data.borrow_mut(),
        };
        unsafe {
            convert_err(ffi::gpgme_op_card_edit(
                self.as_raw(),
                key.as_raw(),
                Some(callbacks::edit_cb::<E>),
                ptr::addr_of_mut!(hook).cast(),
                (*hook.response).as_raw(),
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_op_edit`](https://www.gnupg.org/documentation/manuals/gpgme/Deprecated-Functions.html#index-gpgme_005fop_005fedit)
    #[inline]
    #[deprecated(since = "0.9.2", note = "use `interact` instead")]
    pub fn edit_key_with<'a, D>(
        &mut self,
        key: &Key,
        editor: impl edit::Editor,
        data: D,
    ) -> Result<()>
    where
        D: IntoData<'a>,
    {
        #[allow(deprecated)]
        self.edit_key(key, edit::EditorWrapper::new(editor), data)
    }

    /// Upstream documentation:
    /// [`gpgme_op_card_edit`](https://www.gnupg.org/documentation/manuals/gpgme/Deprecated-Functions.html#index-gpgme_005fop_005fcard_005fedit)
    #[inline]
    #[deprecated(since = "0.9.2", note = "use `interact_with_card` instead")]
    pub fn edit_card_key_with<'a, D>(
        &mut self,
        key: &Key,
        editor: impl edit::Editor,
        data: D,
    ) -> Result<()>
    where
        D: IntoData<'a>,
    {
        #[allow(deprecated)]
        self.edit_card_key(key, edit::EditorWrapper::new(editor), data)
    }

    /// Upstream documentation:
    /// [`gpgme_op_interact`](https://www.gnupg.org/documentation/manuals/gpgme/Advanced-Key-Editing.html#index-gpgme_005fop_005finteract)
    #[inline]
    pub fn interact<'a, I, D>(&mut self, key: &Key, interactor: I, data: D) -> Result<()>
    where
        I: Interactor,
        D: IntoData<'a>,
    {
        self.interact_with_flags(Some(key), interactor, data, crate::InteractFlags::empty())
    }

    /// Upstream documentation:
    /// [`gpgme_op_interact`](https://www.gnupg.org/documentation/manuals/gpgme/Advanced-Key-Editing.html#index-gpgme_005fop_005finteract)
    #[inline]
    pub fn interact_with_card<'a, I, D>(&mut self, key: &Key, interactor: I, data: D) -> Result<()>
    where
        I: Interactor,
        D: IntoData<'a>,
    {
        self.interact_with_flags(Some(key), interactor, data, crate::InteractFlags::CARD)
    }

    /// Upstream documentation:
    /// [`gpgme_op_interact`](https://www.gnupg.org/documentation/manuals/gpgme/Advanced-Key-Editing.html#index-gpgme_005fop_005finteract)
    #[inline]
    pub fn interact_with_flags<'a, I, D>(
        &mut self,
        key: Option<&Key>,
        interactor: I,
        data: D,
        flags: crate::InteractFlags,
    ) -> Result<()>
    where
        I: Interactor,
        D: IntoData<'a>,
    {
        let mut data = data.into_data()?;
        let mut hook = callbacks::InteractorHook {
            inner: interactor.into(),
            response: data.borrow_mut(),
        };
        unsafe {
            convert_err(ffi::gpgme_op_interact(
                self.as_raw(),
                key.map_or(ptr::null_mut(), |k| k.as_raw()),
                flags.bits(),
                Some(callbacks::interact_cb::<I>),
                ptr::addr_of_mut!(hook).cast(),
                (*hook.response).as_raw(),
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_op_delete`](https://www.gnupg.org/documentation/manuals/gpgme/Deleting-Keys.html#index-gpgme_005fop_005fdelete)
    #[inline]
    pub fn delete_key(&mut self, key: &Key) -> Result<()> {
        unsafe { convert_err(ffi::gpgme_op_delete(self.as_raw(), key.as_raw(), 0)) }
    }

    /// Upstream documentation:
    /// [`gpgme_op_delete`](https://www.gnupg.org/documentation/manuals/gpgme/Deleting-Keys.html#index-gpgme_005fop_005fdelete)
    #[inline]
    pub fn delete_secret_key(&mut self, key: &Key) -> Result<()> {
        unsafe { convert_err(ffi::gpgme_op_delete(self.as_raw(), key.as_raw(), 1)) }
    }

    /// Upstream documentation:
    /// [`gpgme_op_delete_ext`](https://www.gnupg.org/documentation/manuals/gpgme/Deleting-Keys.html#index-gpgme_005fop_005fdelete_005fext)
    #[inline]
    pub fn delete_key_with_flags(&mut self, key: &Key, flags: crate::DeleteKeyFlags) -> Result<()> {
        unsafe {
            convert_err(ffi::gpgme_op_delete_ext(
                self.as_raw(),
                key.as_raw(),
                flags.bits(),
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_op_import`](https://www.gnupg.org/documentation/manuals/gpgme/Importing-Keys.html#index-gpgme_005fop_005fimport)
    #[inline]
    pub fn import<'a, D>(&mut self, src: D) -> Result<results::ImportResult>
    where
        D: IntoData<'a>,
    {
        let mut src = src.into_data()?;
        unsafe {
            convert_err(ffi::gpgme_op_import(
                self.as_raw(),
                src.borrow_mut().as_raw(),
            ))?;
        }
        Ok(self.get_result().unwrap())
    }

    /// Upstream documentation:
    /// [`gpgme_op_import_keys`](https://www.gnupg.org/documentation/manuals/gpgme/Importing-Keys.html#index-gpgme_005fop_005fimport_005fkeys)
    pub fn import_keys<'k, I>(&mut self, keys: I) -> Result<results::ImportResult>
    where
        I: IntoIterator<Item = &'k Key>,
    {
        let mut ptrs: SmallVec<_> = keys.into_iter().map(Key::as_raw).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            convert_err(ffi::gpgme_op_import_keys(self.as_raw(), keys))?;
        }
        Ok(self.get_result().unwrap())
    }

    /// Upstream documentation:
    /// [`gpgme_op_receive_keys`](https://www.gnupg.org/documentation/manuals/gpgme/Importing-Keys.html#index-gpgme_005fop_005freceive_005fkeys)
    #[cfg(feature = "v1_17")]
    pub fn import_remote_keys<I>(&mut self, uids: I) -> Result<results::ImportResult>
    where
        I: IntoIterator,
        I::Item: CStrArgument,
    {
        let uids: SmallVec<_> = uids.into_iter().map(|s| s.into_cstr()).collect();
        let uids: SmallVec<_> = uids
            .iter()
            .map(|s| s.as_ref().as_ptr())
            .chain(Some(ptr::null()))
            .collect();
        unsafe {
            convert_err(ffi::gpgme_op_receive_keys(self.as_raw(), uids.as_ptr()))?;
        }
        Ok(self.get_result().unwrap())
    }

    /// Upstream documentation:
    /// [`gpgme_op_export_ext`](https://www.gnupg.org/documentation/manuals/gpgme/Exporting-Keys.html#index-gpgme_005fop_005fexport_005fext)
    #[inline]
    pub fn export_all_extern<I>(&mut self, mode: ExportMode) -> Result<()>
    where
        I: IntoIterator,
        I::Item: CStrArgument,
    {
        self.export_(None::<&CStr>, mode | ExportMode::EXTERN, None)
    }

    /// Upstream documentation:
    /// [`gpgme_op_export_ext`](https://www.gnupg.org/documentation/manuals/gpgme/Exporting-Keys.html#index-gpgme_005fop_005fexport_005fext)
    #[inline]
    pub fn export_extern<I>(&mut self, patterns: I, mode: ExportMode) -> Result<()>
    where
        I: IntoIterator,
        I::Item: CStrArgument,
    {
        let patterns: SmallVec<_> = patterns.into_iter().map(|s| s.into_cstr()).collect();
        self.export_(&patterns, mode | ExportMode::EXTERN, None)
    }

    /// Upstream documentation:
    /// [`gpgme_op_export_ext`](https://www.gnupg.org/documentation/manuals/gpgme/Exporting-Keys.html#index-gpgme_005fop_005fexport_005fext)
    #[inline]
    pub fn export_all<'a, D>(&mut self, mode: ExportMode, dst: D) -> Result<()>
    where
        D: IntoData<'a>,
    {
        let mut dst = dst.into_data()?;
        self.export_(None::<&CStr>, mode, Some(dst.borrow_mut()))
    }

    /// Upstream documentation:
    /// [`gpgme_op_export_ext`](https://www.gnupg.org/documentation/manuals/gpgme/Exporting-Keys.html#index-gpgme_005fop_005fexport_005fext)
    #[inline]
    pub fn export<'a, I, D>(&mut self, patterns: I, mode: ExportMode, dst: D) -> Result<()>
    where
        I: IntoIterator,
        I::Item: CStrArgument,
        D: IntoData<'a>,
    {
        let mut dst = dst.into_data()?;
        let patterns: SmallVec<_> = patterns.into_iter().map(|s| s.into_cstr()).collect();
        self.export_(&patterns, mode, Some(dst.borrow_mut()))
    }

    fn export_<I>(
        &mut self,
        patterns: I,
        mode: ExportMode,
        dst: Option<&mut Data<'_>>,
    ) -> Result<()>
    where
        I: IntoIterator,
        I::Item: AsRef<CStr>,
    {
        let dst = dst.map_or(ptr::null_mut(), |d| d.as_raw());
        let mut patterns: SmallVec<_> = patterns.into_iter().map(|s| s.as_ref().as_ptr()).collect();
        let ptr = if !patterns.is_empty() {
            patterns.push(ptr::null());
            patterns.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            convert_err(ffi::gpgme_op_export_ext(
                self.as_raw(),
                ptr,
                mode.bits(),
                dst,
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_op_export_keys`](https://www.gnupg.org/documentation/manuals/gpgme/Exporting-Keys.html#index-gpgme_005fop_005fexport_005fkeys)
    #[inline]
    pub fn export_keys_extern<'k, I>(&mut self, keys: I, mode: ExportMode) -> Result<()>
    where
        I: IntoIterator<Item = &'k Key>,
    {
        self.export_keys_(keys, mode | ExportMode::EXTERN, None)
    }

    /// Upstream documentation:
    /// [`gpgme_op_export_keys`](https://www.gnupg.org/documentation/manuals/gpgme/Exporting-Keys.html#index-gpgme_005fop_005fexport_005fkeys)
    #[inline]
    pub fn export_keys<'k, 'a, I, D>(&mut self, keys: I, mode: ExportMode, dst: D) -> Result<()>
    where
        I: IntoIterator<Item = &'k Key>,
        D: IntoData<'a>,
    {
        let mut dst = dst.into_data()?;
        self.export_keys_(keys, mode, Some(dst.borrow_mut()))
    }

    fn export_keys_<'k, I>(
        &mut self,
        keys: I,
        mode: ExportMode,
        dst: Option<&mut Data<'_>>,
    ) -> Result<()>
    where
        I: IntoIterator<Item = &'k Key>,
    {
        let dst = dst.map_or(ptr::null_mut(), |d| d.as_raw());
        let mut ptrs: SmallVec<_> = keys.into_iter().map(Key::as_raw).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        unsafe {
            convert_err(ffi::gpgme_op_export_keys(
                self.as_raw(),
                keys,
                mode.bits(),
                dst,
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_set_sender`](https://www.gnupg.org/documentation/manuals/gpgme/Setting-the-Sender.html#index-gpgme_005fset_005fsender)
    #[inline]
    pub fn clear_sender(&mut self) -> Result<()> {
        unsafe { convert_err(ffi::gpgme_set_sender(self.as_raw(), ptr::null())) }
    }

    /// Upstream documentation:
    /// [`gpgme_set_sender`](https://www.gnupg.org/documentation/manuals/gpgme/Setting-the-Sender.html#index-gpgme_005fset_005fsender)
    #[inline]
    pub fn set_sender(&mut self, sender: impl CStrArgument) -> Result<()> {
        let sender = sender.into_cstr();
        unsafe {
            convert_err(ffi::gpgme_set_sender(
                self.as_raw(),
                sender.as_ref().as_ptr(),
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_get_sender`](https://www.gnupg.org/documentation/manuals/gpgme/Setting-the-Sender.html#index-gpgme_005fget_005fsender)
    #[inline]
    pub fn sender(&self) -> Result<&str, Option<Utf8Error>> {
        self.sender_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    /// Upstream documentation:
    /// [`gpgme_get_sender`](https://www.gnupg.org/documentation/manuals/gpgme/Setting-the-Sender.html#index-gpgme_005fget_005fsender)
    #[inline]
    pub fn sender_raw(&self) -> Option<&CStr> {
        unsafe {
            ffi::gpgme_get_sender(self.as_raw())
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_signers_clear`](https://www.gnupg.org/documentation/manuals/gpgme/Selecting-Signers.html#index-gpgme_005fsigners_005fclear)
    #[inline]
    pub fn clear_signers(&mut self) {
        unsafe { ffi::gpgme_signers_clear(self.as_raw()) }
    }

    /// Upstream documentation:
    /// [`gpgme_signers_add`](https://www.gnupg.org/documentation/manuals/gpgme/Selecting-Signers.html#index-gpgme_005fsigners_005fadd)
    #[inline]
    pub fn add_signer(&mut self, key: &Key) -> Result<()> {
        unsafe { convert_err(ffi::gpgme_signers_add(self.as_raw(), key.as_raw())) }
    }

    /// Upstream documentation:
    /// [`gpgme_signers_enum`](https://www.gnupg.org/documentation/manuals/gpgme/Selecting-Signers.html#index-gpgme_005fsigners_005fenum)
    #[inline]
    pub fn signers(&self) -> Signers<'_> {
        Signers {
            ctx: self,
            current: Some(0),
        }
    }

    /// Upstream documentation:
    /// [`gpgme_sig_notation_clear`](https://www.gnupg.org/documentation/manuals/gpgme/Signature-Notation-Data.html#index-gpgme_005fsig_005fnotation_005fclear)
    #[inline]
    pub fn clear_signature_notations(&mut self) {
        unsafe {
            ffi::gpgme_sig_notation_clear(self.as_raw());
        }
    }

    /// Upstream documentation:
    /// [`gpgme_sig_notation_add`](https://www.gnupg.org/documentation/manuals/gpgme/Signature-Notation-Data.html#index-gpgme_005fsig_005fnotation_005fadd)
    #[inline]
    pub fn add_signature_notation(
        &mut self,
        name: impl CStrArgument,
        value: impl CStrArgument,
        flags: crate::SignatureNotationFlags,
    ) -> Result<()> {
        let name = name.into_cstr();
        let value = value.into_cstr();
        unsafe {
            convert_err(ffi::gpgme_sig_notation_add(
                self.as_raw(),
                name.as_ref().as_ptr(),
                value.as_ref().as_ptr(),
                flags.bits(),
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_sig_notation_add`](https://www.gnupg.org/documentation/manuals/gpgme/Signature-Notation-Data.html#index-gpgme_005fsig_005fnotation_005fadd)
    #[inline]
    pub fn add_signature_policy_url(
        &mut self,
        url: impl CStrArgument,
        critical: bool,
    ) -> Result<()> {
        let url = url.into_cstr();
        unsafe {
            let critical = if critical {
                ffi::GPGME_SIG_NOTATION_CRITICAL
            } else {
                0
            };
            convert_err(ffi::gpgme_sig_notation_add(
                self.as_raw(),
                ptr::null(),
                url.as_ref().as_ptr(),
                critical,
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_sig_notation_get`](https://www.gnupg.org/documentation/manuals/gpgme/Signature-Notation-Data.html#index-gpgme_005fsig_005fnotation_005fget)
    #[inline]
    pub fn signature_policy_url(&self) -> Result<&str, Option<Utf8Error>> {
        self.signature_policy_url_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    /// Upstream documentation:
    /// [`gpgme_sig_notation_get`](https://www.gnupg.org/documentation/manuals/gpgme/Signature-Notation-Data.html#index-gpgme_005fsig_005fnotation_005fget)
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

    /// Upstream documentation:
    /// [`gpgme_sig_notation_get`](https://www.gnupg.org/documentation/manuals/gpgme/Signature-Notation-Data.html#index-gpgme_005fsig_005fnotation_005fget)
    #[inline]
    pub fn signature_notations(&self) -> SignatureNotations<'_> {
        unsafe { SignatureNotations::from_list(ffi::gpgme_sig_notation_get(self.as_raw())) }
    }

    /// Creates a clear text signature.
    ///
    /// Upstream documentation:
    /// [`gpgme_op_sign`](https://www.gnupg.org/documentation/manuals/gpgme/Creating-a-Signature.html#index-gpgme_005fop_005fsign)
    #[inline]
    pub fn sign_clear<'p, 't, P, T>(
        &mut self,
        plaintext: P,
        signedtext: T,
    ) -> Result<results::SigningResult>
    where
        P: IntoData<'p>,
        T: IntoData<'t>,
    {
        self.sign(SignMode::Clear, plaintext, signedtext)
    }

    /// Creates a detached signature.
    ///
    /// Upstream documentation:
    /// [`gpgme_op_sign`](https://www.gnupg.org/documentation/manuals/gpgme/Creating-a-Signature.html#index-gpgme_005fop_005fsign)
    #[inline]
    pub fn sign_detached<'p, 's, P, S>(
        &mut self,
        plaintext: P,
        signature: S,
    ) -> Result<results::SigningResult>
    where
        P: IntoData<'p>,
        S: IntoData<'s>,
    {
        self.sign(SignMode::Detached, plaintext, signature)
    }

    /// Creates a normal signature.
    ///
    /// Upstream documentation:
    /// [`gpgme_op_sign`](https://www.gnupg.org/documentation/manuals/gpgme/Creating-a-Signature.html#index-gpgme_005fop_005fsign)
    #[inline]
    pub fn sign_normal<'p, 't, P, T>(
        &mut self,
        plaintext: P,
        signedtext: T,
    ) -> Result<results::SigningResult>
    where
        P: IntoData<'p>,
        T: IntoData<'t>,
    {
        self.sign(SignMode::Normal, plaintext, signedtext)
    }

    /// Creates a signature for the text stored in the data object `plaintext` and writes it to the
    /// data object `signature`.
    ///
    /// The type of the signature created is determined by the ASCII armor (or, if that is not set,
    /// by the encoding specified for sig), the text mode attributes set for the context and the
    /// requested signature mode.
    ///
    /// Information about the results of the operation are returned in the `SigningResult`
    /// structure.
    ///
    /// Upstream documentation:
    /// [`gpgme_op_sign`](https://www.gnupg.org/documentation/manuals/gpgme/Creating-a-Signature.html#index-gpgme_005fop_005fsign)
    #[inline]
    pub fn sign<'p, 's, P, S>(
        &mut self,
        mode: crate::SignMode,
        plaintext: P,
        signature: S,
    ) -> Result<results::SigningResult>
    where
        P: IntoData<'p>,
        S: IntoData<'s>,
    {
        let mut signature = signature.into_data()?;
        let mut plain = plaintext.into_data()?;
        unsafe {
            convert_err(ffi::gpgme_op_sign(
                self.as_raw(),
                plain.borrow_mut().as_raw(),
                signature.borrow_mut().as_raw(),
                mode.raw(),
            ))?;
        }
        Ok(self.get_result().unwrap())
    }

    /// Upstream documentation:
    /// [`gpgme_op_verify`](https://www.gnupg.org/documentation/manuals/gpgme/Verify.html#index-gpgme_005fop_005fverify)
    #[inline]
    pub fn verify_detached<'s, 't, S, T>(
        &mut self,
        signature: S,
        signedtext: T,
    ) -> Result<results::VerificationResult>
    where
        S: IntoData<'s>,
        T: IntoData<'t>,
    {
        let mut signature = signature.into_data()?;
        let mut signed = signedtext.into_data()?;
        self.verify(signature.borrow_mut(), Some(signed.borrow_mut()), None)
    }

    /// Upstream documentation:
    /// [`gpgme_op_verify`](https://www.gnupg.org/documentation/manuals/gpgme/Verify.html#index-gpgme_005fop_005fverify)
    #[inline]
    pub fn verify_opaque<'s, 'p, S, P>(
        &mut self,
        signedtext: S,
        plaintext: P,
    ) -> Result<results::VerificationResult>
    where
        S: IntoData<'s>,
        P: IntoData<'p>,
    {
        let mut signed = signedtext.into_data()?;
        let mut plain = plaintext.into_data()?;
        self.verify(signed.borrow_mut(), None, Some(plain.borrow_mut()))
    }

    fn verify(
        &mut self,
        signature: &mut Data<'_>,
        signedtext: Option<&mut Data<'_>>,
        plaintext: Option<&mut Data<'_>>,
    ) -> Result<results::VerificationResult> {
        unsafe {
            let signed = signedtext.map_or(ptr::null_mut(), |d| d.as_raw());
            let plain = plaintext.map_or(ptr::null_mut(), |d| d.as_raw());
            convert_err(ffi::gpgme_op_verify(
                self.as_raw(),
                signature.as_raw(),
                signed,
                plain,
            ))?;
        }
        Ok(self.get_result().unwrap())
    }

    /// Upstream documentation:
    /// [`gpgme_op_verify_ext`](https://www.gnupg.org/documentation/manuals/gpgme/Verify.html#index-gpgme_005fop_005fverify_005fext)
    #[cfg(feature = "v1_19")]
    fn verify_with_flags(
        &mut self,
        signature: &mut Data<'_>,
        signedtext: Option<&mut Data<'_>>,
        plaintext: Option<&mut Data<'_>>,
        flags: crate::VerifyFlags,
    ) -> Result<results::VerificationResult> {
        unsafe {
            let signed = signedtext.map_or(ptr::null_mut(), |d| d.as_raw());
            let plain = plaintext.map_or(ptr::null_mut(), |d| d.as_raw());
            convert_err(ffi::gpgme_op_verify_ext(
                self.as_raw(),
                flags.bits(),
                signature.as_raw(),
                signed,
                plain,
            ))?;
        }
        Ok(self.get_result().unwrap())
    }

    /// Encrypts a message for the specified recipients.
    ///
    /// Upstream documentation:
    /// [`gpgme_op_encrypt`](https://www.gnupg.org/documentation/manuals/gpgme/Encrypting-a-Plaintext.html#index-gpgme_005fop_005fencrypt)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use gpgme::{Context, Data, Protocol};
    ///
    /// let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
    /// let key = ctx.get_key("[some key fingerprint]")?;
    /// let (plaintext, mut ciphertext) = ("Hello, World!", Vec::new());
    /// ctx.encrypt(Some(&key), plaintext, &mut ciphertext)?;
    /// # Ok::<(), gpgme::Error>(())
    /// ```
    #[inline]
    pub fn encrypt<'k, 'p, 'c, I, P, C>(
        &mut self,
        recp: I,
        plaintext: P,
        ciphertext: C,
    ) -> Result<results::EncryptionResult>
    where
        I: IntoIterator<Item = &'k Key>,
        P: IntoData<'p>,
        C: IntoData<'c>,
    {
        self.encrypt_with_flags(recp, plaintext, ciphertext, crate::EncryptFlags::empty())
    }

    /// Upstream documentation:
    /// [`gpgme_op_encrypt`](https://www.gnupg.org/documentation/manuals/gpgme/Encrypting-a-Plaintext.html#index-gpgme_005fop_005fencrypt)
    pub fn encrypt_with_flags<'k, 'p, 'c, I, P, C>(
        &mut self,
        recp: I,
        plaintext: P,
        ciphertext: C,
        flags: crate::EncryptFlags,
    ) -> Result<results::EncryptionResult>
    where
        I: IntoIterator<Item = &'k Key>,
        P: IntoData<'p>,
        C: IntoData<'c>,
    {
        let mut plain = plaintext.into_data()?;
        let mut cipher = ciphertext.into_data()?;
        let mut ptrs: SmallVec<_> = recp.into_iter().map(Key::as_raw).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };

        unsafe {
            convert_err(ffi::gpgme_op_encrypt(
                self.as_raw(),
                keys,
                flags.bits(),
                plain.borrow_mut().as_raw(),
                cipher.borrow_mut().as_raw(),
            ))?;
        }
        Ok(self.get_result().unwrap())
    }

    /// Upstream documentation:
    /// [`gpgme_op_encrypt`](https://www.gnupg.org/documentation/manuals/gpgme/Encrypting-a-Plaintext.html#index-gpgme_005fop_005fencrypt)
    #[inline]
    pub fn encrypt_symmetric<'p, 'c, P, C>(&mut self, plaintext: P, ciphertext: C) -> Result<()>
    where
        P: IntoData<'p>,
        C: IntoData<'c>,
    {
        self.encrypt_symmetric_with_flags(plaintext, ciphertext, crate::EncryptFlags::empty())
    }

    /// Upstream documentation:
    /// [`gpgme_op_encrypt`](https://www.gnupg.org/documentation/manuals/gpgme/Encrypting-a-Plaintext.html#index-gpgme_005fop_005fencrypt)
    #[inline]
    pub fn encrypt_symmetric_with_flags<'p, 'c, P, C>(
        &mut self,
        plaintext: P,
        ciphertext: C,
        flags: crate::EncryptFlags,
    ) -> Result<()>
    where
        P: IntoData<'p>,
        C: IntoData<'c>,
    {
        self.encrypt_with_flags(None, plaintext, ciphertext, flags)?;
        Ok(())
    }

    /// Encrypts and signs a message for the specified recipients.
    ///
    /// Upstream documentation:
    /// [`gpgme_op_encrypt_sign`](https://www.gnupg.org/documentation/manuals/gpgme/Encrypting-a-Plaintext.html#index-gpgme_005fop_005fencrypt_005fsign)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use gpgme::{Context, Protocol};
    ///
    /// let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
    /// let key = ctx.get_key("[some key fingerprint]")?;
    /// let (plaintext, mut ciphertext) = ("Hello, World!", Vec::new());
    /// ctx.sign_and_encrypt(Some(&key), plaintext, &mut ciphertext)?;
    /// # Ok::<(), gpgme::Error>(())
    /// ```
    #[inline]
    pub fn sign_and_encrypt<'k, 'p, 'c, I, P, C>(
        &mut self,
        recp: I,
        plaintext: P,
        ciphertext: C,
    ) -> Result<(results::EncryptionResult, results::SigningResult)>
    where
        I: IntoIterator<Item = &'k Key>,
        P: IntoData<'p>,
        C: IntoData<'c>,
    {
        self.sign_and_encrypt_with_flags(recp, plaintext, ciphertext, crate::EncryptFlags::empty())
    }

    /// Upstream documentation:
    /// [`gpgme_op_encrypt_sign`](https://www.gnupg.org/documentation/manuals/gpgme/Encrypting-a-Plaintext.html#index-gpgme_005fop_005fencrypt_005fsign)
    pub fn sign_and_encrypt_with_flags<'k, 'p, 'c, I, P, C>(
        &mut self,
        recp: I,
        plaintext: P,
        ciphertext: C,
        flags: crate::EncryptFlags,
    ) -> Result<(results::EncryptionResult, results::SigningResult)>
    where
        I: IntoIterator<Item = &'k Key>,
        P: IntoData<'p>,
        C: IntoData<'c>,
    {
        let mut plain = plaintext.into_data()?;
        let mut cipher = ciphertext.into_data()?;
        let mut ptrs: SmallVec<_> = recp.into_iter().map(Key::as_raw).collect();
        let keys = if !ptrs.is_empty() {
            ptrs.push(ptr::null_mut());
            ptrs.as_mut_ptr()
        } else {
            ptr::null_mut()
        };

        unsafe {
            convert_err(ffi::gpgme_op_encrypt_sign(
                self.as_raw(),
                keys,
                flags.bits(),
                plain.borrow_mut().as_raw(),
                cipher.borrow_mut().as_raw(),
            ))?;
        }
        Ok((self.get_result().unwrap(), self.get_result().unwrap()))
    }

    /// Decrypts a message.
    ///
    /// Upstream documentation:
    /// [`gpgme_op_decrypt`](https://www.gnupg.org/documentation/manuals/gpgme/Decrypt.html#index-gpgme_005fop_005fdecrypt)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use gpgme::{Context, Data, Protocol};
    ///
    /// let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
    /// let mut cipher = Data::load("some file")?;
    /// let mut plain = Vec::new();
    /// ctx.decrypt(&mut cipher, &mut plain)?;
    /// # Ok::<(), gpgme::Error>(())
    /// ```
    #[inline]
    pub fn decrypt<'c, 'p, C, P>(
        &mut self,
        ciphertext: C,
        plaintext: P,
    ) -> Result<results::DecryptionResult>
    where
        C: IntoData<'c>,
        P: IntoData<'p>,
    {
        let mut cipher = ciphertext.into_data()?;
        let mut plain = plaintext.into_data()?;
        unsafe {
            convert_err(ffi::gpgme_op_decrypt(
                self.as_raw(),
                cipher.borrow_mut().as_raw(),
                plain.borrow_mut().as_raw(),
            ))?;
        }
        Ok(self.get_result().unwrap())
    }

    /// Upstream documentation:
    /// [`gpgme_op_decrypt_ext`](https://www.gnupg.org/documentation/manuals/gpgme/Decrypt.html#index-gpgme_005fop_005fdecrypt_005fext)
    #[inline]
    pub fn decrypt_with_flags<'c, 'p, C, P>(
        &mut self,
        ciphertext: C,
        plaintext: P,
        flags: crate::DecryptFlags,
    ) -> Result<results::DecryptionResult>
    where
        C: IntoData<'c>,
        P: IntoData<'p>,
    {
        let mut cipher = ciphertext.into_data()?;
        let mut plain = plaintext.into_data()?;
        unsafe {
            convert_err(ffi::gpgme_op_decrypt_ext(
                self.as_raw(),
                flags.bits(),
                cipher.borrow_mut().as_raw(),
                plain.borrow_mut().as_raw(),
            ))?;
        }
        Ok(self.get_result().unwrap())
    }

    /// Decrypts and verifies a message.
    ///
    /// Upstream documentation:
    /// [`gpgme_op_decrypt_verify`](https://www.gnupg.org/documentation/manuals/gpgme/Decrypt-and-Verify.html#index-gpgme_005fop_005fdecrypt_005fverify)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use gpgme::{Context, Data, Protocol};
    ///
    /// let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
    /// let mut cipher = Data::load("some file")?;
    /// let mut plain = Vec::new();
    /// ctx.decrypt_and_verify(&mut cipher, &mut plain)?;
    /// # Ok::<(), gpgme::Error>(())
    /// ```
    #[inline]
    pub fn decrypt_and_verify<'c, 'p, C, P>(
        &mut self,
        ciphertext: C,
        plaintext: P,
    ) -> Result<(results::DecryptionResult, results::VerificationResult)>
    where
        C: IntoData<'c>,
        P: IntoData<'p>,
    {
        let mut cipher = ciphertext.into_data()?;
        let mut plain = plaintext.into_data()?;
        unsafe {
            convert_err(ffi::gpgme_op_decrypt_verify(
                self.as_raw(),
                cipher.borrow_mut().as_raw(),
                plain.borrow_mut().as_raw(),
            ))?;
        }
        Ok((self.get_result().unwrap(), self.get_result().unwrap()))
    }

    /// Upstream documentation:
    /// [`gpgme_op_decrypt_ext`](https://www.gnupg.org/documentation/manuals/gpgme/Decrypt.html#index-gpgme_005fop_005fdecrypt_005fext)
    #[inline]
    pub fn decrypt_and_verify_with_flags<'c, 'p, C, P>(
        &mut self,
        ciphertext: C,
        plaintext: P,
        flags: crate::DecryptFlags,
    ) -> Result<(results::DecryptionResult, results::VerificationResult)>
    where
        C: IntoData<'c>,
        P: IntoData<'p>,
    {
        self.decrypt_with_flags(ciphertext, plaintext, flags)?;
        Ok((self.get_result().unwrap(), self.get_result().unwrap()))
    }

    /// Upstream documentation:
    /// [`gpgme_op_query_swdb`](https://www.gnupg.org/documentation/manuals/gpgme/Checking-for-updates.html#index-gpgme_005fop_005fquery_005fswdb)
    #[inline]
    pub fn query_swdb(
        &mut self,
        name: Option<impl CStrArgument>,
        installed_ver: Option<impl CStrArgument>,
    ) -> Result<results::QuerySwdbResult> {
        let name = name.map(|s| s.into_cstr());
        let iversion = installed_ver.map(|s| s.into_cstr());
        unsafe {
            let name = name.as_ref().map_or(ptr::null(), |s| s.as_ref().as_ptr());
            let iversion = iversion
                .as_ref()
                .map_or(ptr::null(), |s| s.as_ref().as_ptr());
            convert_err(ffi::gpgme_op_query_swdb(self.as_raw(), name, iversion, 0))?;
        }
        Ok(self.get_result().unwrap())
    }

    /// Upstream documentation:
    /// [`gpgme_op_getauditlog`](https://www.gnupg.org/documentation/manuals/gpgme/Additional-Logs.html#index-gpgme_005fop_005fgetauditlog)
    #[inline]
    pub fn get_audit_log<'a, D>(&mut self, dst: D, flags: crate::AuditLogFlags) -> Result<()>
    where
        D: IntoData<'a>,
    {
        let mut dst = dst.into_data()?;
        unsafe {
            convert_err(ffi::gpgme_op_getauditlog(
                self.as_raw(),
                dst.borrow_mut().as_raw(),
                flags.bits(),
            ))
        }
    }

    fn get_result<R: crate::OpResult>(&self) -> Option<R> {
        R::from_context(self)
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("raw", &self.as_raw())
            .field("protocol", &self.protocol())
            .field("armor", &self.armor())
            .field("text_mode", &self.text_mode())
            .field("engine", &self.engine_info())
            .finish()
    }
}

/// An iterator type yielding `Key`s returned by a key listing operation.
#[derive(Debug)]
pub struct Keys<'ctx, D = ()> {
    ctx: &'ctx mut Context,
    _src: D,
}

impl<D> Drop for Keys<'_, D> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_op_keylist_end(self.ctx.as_raw());
        }
    }
}

impl<D> Keys<'_, D> {
    /// Upstream documentation:
    /// [`gpgme_op_keylist_end`](https://www.gnupg.org/documentation/manuals/gpgme/Listing-Keys.html#index-gpgme_005fop_005fkeylist_005fend)
    #[inline]
    pub fn finish(self) -> Result<results::KeyListResult> {
        let this = ManuallyDrop::new(self);
        unsafe {
            convert_err(ffi::gpgme_op_keylist_end(this.ctx.as_raw()))?;
        }
        Ok(this.ctx.get_result().unwrap())
    }
}

impl<'ctx> Keys<'ctx, ()> {
    /// Upstream documentation:
    /// [`gpgme_op_keylist_from_data_start`](https://www.gnupg.org/documentation/manuals/gpgme/Listing-Keys.html#index-gpgme_005fop_005fkeylist_005ffrom_005fdata_005fstart)
    #[inline]
    pub fn from_data<'d, D>(ctx: &'ctx mut Context, src: D) -> Result<Keys<'d, D::Output>>
    where
        D: IntoData<'d>,
        'ctx: 'd,
    {
        let mut src = src.into_data()?;
        unsafe {
            convert_err(ffi::gpgme_op_keylist_from_data_start(
                ctx.as_raw(),
                src.borrow_mut().as_raw(),
                0,
            ))?;
        }
        Ok(Keys { _src: src, ctx })
    }
}

impl<D> Iterator for Keys<'_, D> {
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

impl<D> FusedIterator for Keys<'_, D> {}

/// An iterator type yielding the `Key`s that would be used in a signing operation for a `Context`.
#[derive(Clone)]
pub struct Signers<'ctx> {
    ctx: &'ctx Context,
    current: Option<libc::c_int>,
}

impl Iterator for Signers<'_> {
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
        self.current = self
            .current
            .and_then(|x| n.value_into().ok().and_then(|n| x.checked_add(n)));
        self.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.current.map_or((0, Some(0)), |c| {
            let total = unsafe { ffi::gpgme_signers_count(self.ctx.as_raw()) };
            match usize::try_from(total - (c as libc::c_uint)) {
                Ok(v) => (v, Some(v)),
                Err(_) => (usize::MAX, None),
            }
        })
    }

    #[inline]
    fn count(self) -> usize {
        self.size_hint().0
    }
}

impl FusedIterator for Signers<'_> {}

impl fmt::Debug for Signers<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// A bundle containing a context for cryptographic operations and storage
/// for various callbacks used by the context.
///
/// Upstream documentation:
/// [`gpgme_ctx_t`](https://www.gnupg.org/documentation/manuals/gpgme/Contexts.html#Contexts)
pub struct ContextWithCallbacks<'a> {
    inner: Context,
    passphrase_hook: Option<Box<dyn Send + 'a>>,
    progress_hook: Option<Box<dyn Send + 'a>>,
    status_hook: Option<Box<dyn Send + 'a>>,
}

impl Drop for ContextWithCallbacks<'_> {
    fn drop(&mut self) {
        (**self).clear_passphrase_provider();
        (**self).clear_progress_reporter();
        (**self).clear_status_handler();
    }
}

impl<'a> ContextWithCallbacks<'a> {
    /// Upstream documentation:
    /// [`gpgme_set_passphrase_cb`](https://www.gnupg.org/documentation/manuals/gpgme/Passphrase-Callback.html#index-gpgme_005fset_005fpassphrase_005fcb)
    pub fn clear_passphrase_provider(&mut self) {
        (**self).clear_passphrase_provider();
        self.passphrase_hook.take();
    }

    /// Upstream documentation:
    /// [`gpgme_set_passphrase_cb`](https://www.gnupg.org/documentation/manuals/gpgme/Passphrase-Callback.html#index-gpgme_005fset_005fpassphrase_005fcb)
    pub fn set_passphrase_provider<P>(&mut self, provider: P)
    where
        P: PassphraseProvider + 'a,
    {
        let mut hook = Box::new(callbacks::Hook::from(provider));
        unsafe {
            ffi::gpgme_set_passphrase_cb(
                self.as_raw(),
                Some(callbacks::passphrase_cb::<P>),
                ptr::addr_of_mut!(*hook).cast(),
            );
        }
        self.passphrase_hook = Some(hook);
    }

    /// Upstream documentation:
    /// [`gpgme_set_progress_cb`](https://www.gnupg.org/documentation/manuals/gpgme/Progress-Meter-Callback.html#index-gpgme_005fset_005fprogress_005fcb)
    pub fn clear_progress_reporter(&mut self) {
        (**self).clear_progress_reporter();
        self.progress_hook.take();
    }

    /// Upstream documentation:
    /// [`gpgme_set_progress_cb`](https://www.gnupg.org/documentation/manuals/gpgme/Progress-Meter-Callback.html#index-gpgme_005fset_005fprogress_005fcb)
    pub fn set_progress_reporter<H>(&mut self, handler: H)
    where
        H: ProgressReporter + 'a,
    {
        let mut hook = Box::new(callbacks::Hook::from(handler));
        unsafe {
            ffi::gpgme_set_progress_cb(
                self.as_raw(),
                Some(callbacks::progress_cb::<H>),
                ptr::addr_of_mut!(*hook).cast(),
            );
        }
        self.progress_hook = Some(hook);
    }

    /// Upstream documentation:
    /// [`gpgme_set_status_cb`](https://www.gnupg.org/documentation/manuals/gpgme/Status-Message-Callback.html#index-gpgme_005fset_005fstatus_005fcb)
    pub fn clear_status_handler(&mut self) {
        (**self).clear_status_handler();
        self.status_hook.take();
    }

    /// Upstream documentation:
    /// [`gpgme_set_status_cb`](https://www.gnupg.org/documentation/manuals/gpgme/Status-Message-Callback.html#index-gpgme_005fset_005fstatus_005fcb)
    pub fn set_status_handler<H>(&mut self, handler: H)
    where
        H: StatusHandler + 'a,
    {
        let mut hook = Box::new(callbacks::Hook::from(handler));
        unsafe {
            ffi::gpgme_set_status_cb(
                self.as_raw(),
                Some(callbacks::status_cb::<H>),
                ptr::addr_of_mut!(*hook).cast(),
            );
        }
        self.status_hook = Some(hook);
    }

    /// Returns the inner `Context` object.
    ///
    /// All currently set callbacks are cleared by this method.
    pub fn into_inner(mut self) -> Context {
        self.clear_passphrase_provider();
        self.clear_progress_reporter();
        self.clear_status_handler();
        let this = ManuallyDrop::new(self);
        unsafe { Context::from_raw(this.as_raw()) }
    }
}

impl From<Context> for ContextWithCallbacks<'_> {
    fn from(inner: Context) -> Self {
        Self {
            passphrase_hook: None,
            progress_hook: None,
            status_hook: None,
            inner,
        }
    }
}

impl Deref for ContextWithCallbacks<'_> {
    type Target = Context;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ContextWithCallbacks<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl fmt::Debug for ContextWithCallbacks<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.inner, f)
    }
}

fn with_joined_cstr<R, F, I>(strings: I, f: F) -> R
where
    I: IntoIterator,
    I::Item: CStrArgument,
    F: FnOnce(Option<&CStr>, usize) -> R,
{
    let mut strings = strings.into_iter().fuse();
    match (strings.next(), strings.next()) {
        (Some(first), Some(second)) => {
            let mut count = 2;
            let mut joined = Vec::new();
            joined.extend_from_slice(first.into_cstr().as_ref().to_bytes());
            joined.push(b'\n');
            joined.extend_from_slice(second.into_cstr().as_ref().to_bytes());
            for x in strings {
                joined.push(b'\n');
                joined.extend_from_slice(x.into_cstr().as_ref().to_bytes());
                count += 1;
            }
            f(Some(joined.into_cstr().as_ref()), count)
        }
        (Some(single), None) => f(Some(single.into_cstr().as_ref()), 1),
        _ => f(None, 0),
    }
}
