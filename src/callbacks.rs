#![allow(deprecated)]
use std::{
    ffi::CStr,
    io::{self, prelude::*},
    panic::{self, UnwindSafe},
    str::Utf8Error,
    thread,
};

use static_assertions::assert_obj_safe;

use crate::{
    edit,
    utils::{self, FdWriter},
    Data, Error, Result,
};

assert_obj_safe!(PassphraseProvider);
assert_obj_safe!(ProgressReporter);
assert_obj_safe!(StatusHandler);
assert_obj_safe!(EditInteractor);
assert_obj_safe!(Interactor);

#[derive(Debug, Copy, Clone)]
pub struct PassphraseRequest<'a> {
    uid_hint: Option<&'a CStr>,
    desc: Option<&'a CStr>,
    pub prev_attempt_failed: bool,
}

impl<'a> PassphraseRequest<'a> {
    pub fn user_id_hint(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.uid_hint
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn user_id_hint_raw(&self) -> Option<&'a CStr> {
        self.uid_hint
    }

    pub fn description(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.desc.map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn description_raw(&self) -> Option<&'a CStr> {
        self.desc
    }
}

/// Upstream documentation:
/// [`gpgme_passphrase_cb_t`](https://www.gnupg.org/documentation/manuals/gpgme/Passphrase-Callback.html#index-gpgme_005fpassphrase_005fcb_005ft)
pub trait PassphraseProvider: UnwindSafe + Send {
    fn get_passphrase(&mut self, request: PassphraseRequest<'_>, out: &mut dyn Write)
        -> Result<()>;
}

impl<T: UnwindSafe + Send> PassphraseProvider for T
where
    T: FnMut(PassphraseRequest<'_>, &mut dyn io::Write) -> Result<()>,
{
    fn get_passphrase(
        &mut self,
        request: PassphraseRequest<'_>,
        out: &mut dyn Write,
    ) -> Result<()> {
        (*self)(request, out)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ProgressInfo<'a> {
    what: Option<&'a CStr>,
    pub typ: i64,
    pub current: i64,
    pub total: i64,
}

impl<'a> ProgressInfo<'a> {
    pub fn what(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.what.map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn what_raw(&self) -> Option<&'a CStr> {
        self.what
    }
}

/// Upstream documentation:
/// [`gpgme_progress_cb_t`](https://www.gnupg.org/documentation/manuals/gpgme/Progress-Meter-Callback.html#index-gpgme_005fprogress_005fcb_005ft)
pub trait ProgressReporter: UnwindSafe + Send {
    fn report(&mut self, info: ProgressInfo<'_>);
}

impl<T: UnwindSafe + Send> ProgressReporter for T
where
    T: FnMut(ProgressInfo<'_>),
{
    fn report(&mut self, info: ProgressInfo<'_>) {
        (*self)(info);
    }
}

/// Upstream documentation:
/// [`gpgme_status_cb_t`](https://www.gnupg.org/documentation/manuals/gpgme/Status-Message-Callback.html#index-gpgme_005fstatus_005fcb_005ft)
pub trait StatusHandler: UnwindSafe + Send {
    fn handle(&mut self, keyword: Option<&CStr>, args: Option<&CStr>) -> Result<()>;
}

impl<T: UnwindSafe + Send> StatusHandler for T
where
    T: FnMut(Option<&CStr>, Option<&CStr>) -> Result<()>,
{
    fn handle(&mut self, keyword: Option<&CStr>, args: Option<&CStr>) -> Result<()> {
        (*self)(keyword, args)
    }
}

#[derive(Debug)]
pub struct EditInteractionStatus<'a> {
    pub code: edit::StatusCode,
    args: Option<&'a CStr>,
    pub response: &'a mut Data<'a>,
}

impl<'a> EditInteractionStatus<'a> {
    pub fn args(&self) -> Result<&'a str, Option<Utf8Error>> {
        match self.args {
            Some(s) => s.to_str().map_err(Some),
            None => Err(None),
        }
    }

    pub fn args_raw(&self) -> Option<&'a CStr> {
        self.args
    }
}

/// Upstream documentation:
/// [`gpgme_edit_cb_t`](https://www.gnupg.org/documentation/manuals/gpgme/Deprecated-Functions.html#index-gpgme_005fedit_005fcb_005ft)
#[deprecated(since = "0.9.2")]
pub trait EditInteractor: UnwindSafe + Send {
    fn interact(
        &mut self,
        status: EditInteractionStatus<'_>,
        out: Option<&mut dyn Write>,
    ) -> Result<()>;
}

#[derive(Debug)]
pub struct InteractionStatus<'a> {
    keyword: Option<&'a CStr>,
    args: Option<&'a CStr>,
    pub response: &'a mut Data<'a>,
}

impl<'a> InteractionStatus<'a> {
    pub fn keyword(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.keyword.map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn keyword_raw(&self) -> Option<&'a CStr> {
        self.keyword
    }

    pub fn args(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.args.map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn args_raw(&self) -> Option<&'a CStr> {
        self.args
    }
}

/// Upstream documentation:
/// [`gpgme_interact_cb_t`](https://www.gnupg.org/documentation/manuals/gpgme/Advanced-Key-Editing.html#index-gpgme_005finteract_005fcb_005ft)
pub trait Interactor: UnwindSafe + Send {
    fn interact(
        &mut self,
        status: InteractionStatus<'_>,
        out: Option<&mut dyn Write>,
    ) -> Result<(), Error>;
}

pub(crate) struct Hook<T>(Option<thread::Result<T>>);

impl<T> Drop for Hook<T> {
    fn drop(&mut self) {
        if let Some(Err(err)) = self.0.take() {
            panic::resume_unwind(err);
        }
    }
}

impl<T> From<T> for Hook<T> {
    fn from(hook: T) -> Self {
        Self(Some(Ok(hook)))
    }
}

impl<T: UnwindSafe> Hook<T> {
    fn update<F>(&mut self, f: F) -> ffi::gpgme_error_t
    where
        F: UnwindSafe + FnOnce(&mut T) -> Result<()>,
    {
        let mut provider = match self.0.take() {
            Some(Ok(p)) => p,
            other => {
                self.0 = other;
                return ffi::GPG_ERR_GENERAL;
            }
        };

        let result = panic::catch_unwind(move || {
            let result = f(&mut provider);
            (provider, result)
        });
        match result {
            Ok((provider, result)) => {
                self.0 = Some(Ok(provider));
                result.err().map_or(0, |err| err.raw())
            }
            Err(err) => {
                self.0 = Some(Err(err));
                ffi::GPG_ERR_GENERAL
            }
        }
    }
}

pub(crate) struct PassphraseCbGuard {
    pub ctx: ffi::gpgme_ctx_t,
    pub old: (ffi::gpgme_passphrase_cb_t, *mut libc::c_void),
}

impl Drop for PassphraseCbGuard {
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_set_passphrase_cb(self.ctx, self.old.0, self.old.1);
        }
    }
}

pub(crate) struct ProgressCbGuard {
    pub ctx: ffi::gpgme_ctx_t,
    pub old: (ffi::gpgme_progress_cb_t, *mut libc::c_void),
}

impl Drop for ProgressCbGuard {
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_set_progress_cb(self.ctx, self.old.0, self.old.1);
        }
    }
}

pub(crate) struct StatusCbGuard {
    pub ctx: ffi::gpgme_ctx_t,
    pub old: (ffi::gpgme_status_cb_t, *mut libc::c_void),
}

impl Drop for StatusCbGuard {
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_set_status_cb(self.ctx, self.old.0, self.old.1);
        }
    }
}

pub(crate) struct InteractorHook<'a, I> {
    pub inner: Hook<I>,
    pub response: *mut Data<'a>,
}

pub(crate) unsafe extern "C" fn passphrase_cb<P: PassphraseProvider>(
    hook: *mut libc::c_void,
    uid_hint: *const libc::c_char,
    info: *const libc::c_char,
    was_bad: libc::c_int,
    fd: libc::c_int,
) -> ffi::gpgme_error_t {
    (*hook.cast::<Hook<P>>()).update(move |h| {
        let info = PassphraseRequest {
            uid_hint: utils::convert_raw_str(uid_hint),
            desc: utils::convert_raw_str(info),
            prev_attempt_failed: was_bad != 0,
        };
        let mut writer = FdWriter::new(fd);
        h.get_passphrase(info, &mut writer)
            .and_then(|_| writer.write_all(b"\n").map_err(Error::from))
    })
}

pub(crate) unsafe extern "C" fn progress_cb<H: ProgressReporter>(
    hook: *mut libc::c_void,
    what: *const libc::c_char,
    typ: libc::c_int,
    current: libc::c_int,
    total: libc::c_int,
) {
    (*hook.cast::<Hook<H>>()).update(move |h| {
        let info = ProgressInfo {
            what: utils::convert_raw_str(what),
            typ: typ.into(),
            current: current.into(),
            total: total.into(),
        };
        h.report(info);
        Ok(())
    });
}

pub(crate) unsafe extern "C" fn status_cb<H: StatusHandler>(
    hook: *mut libc::c_void,
    keyword: *const libc::c_char,
    args: *const libc::c_char,
) -> ffi::gpgme_error_t {
    (*hook.cast::<Hook<H>>()).update(move |h| {
        let keyword = utils::convert_raw_str(keyword);
        let args = utils::convert_raw_str(args);
        h.handle(args, keyword)
    })
}

pub(crate) unsafe extern "C" fn edit_cb<E: EditInteractor>(
    hook: *mut libc::c_void,
    status: ffi::gpgme_status_code_t,
    args: *const libc::c_char,
    fd: libc::c_int,
) -> ffi::gpgme_error_t {
    let hook = &mut *hook.cast::<InteractorHook<'_, E>>();
    let response = hook.response;
    hook.inner.update(move |h| {
        let status = EditInteractionStatus {
            code: edit::StatusCode::from_raw(status),
            args: utils::convert_raw_str(args),
            response: &mut *response,
        };
        if fd < 0 {
            h.interact(status, None)
        } else {
            h.interact(status, Some(&mut FdWriter::new(fd)))
        }
    })
}

pub(crate) unsafe extern "C" fn interact_cb<I: Interactor>(
    hook: *mut libc::c_void,
    keyword: *const libc::c_char,
    args: *const libc::c_char,
    fd: libc::c_int,
) -> ffi::gpgme_error_t {
    let hook = &mut *hook.cast::<InteractorHook<'_, I>>();
    let response = hook.response;
    hook.inner.update(move |h| {
        let status = InteractionStatus {
            keyword: utils::convert_raw_str(keyword),
            args: utils::convert_raw_str(args),
            response: &mut *response,
        };
        if fd < 0 {
            h.interact(status, None)
        } else {
            h.interact(status, Some(&mut FdWriter::new(fd)))
        }
    })
}
