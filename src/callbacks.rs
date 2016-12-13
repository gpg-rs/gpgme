use std::ffi::CStr;
use std::io;
use std::io::prelude::*;
use std::panic::{self, UnwindSafe};
use std::slice;
use std::str::Utf8Error;
use std::thread;

use libc;
use conv::{ValueInto, UnwrapOrSaturate};
use ffi;

use {Data, Error};
use {edit, error};
use utils::FdWriter;

#[derive(Debug, Copy, Clone)]
pub struct PassphraseRequest<'a> {
    uid_hint: Option<&'a CStr>,
    desc: Option<&'a CStr>,
    pub prev_attempt_failed: bool,
}

impl<'a> PassphraseRequest<'a> {
    pub fn user_id_hint(&self) -> Result<&'a str, Option<Utf8Error>> {
        self.uid_hint.map_or(Err(None), |s| s.to_str().map_err(Some))
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

pub trait PassphraseProvider: UnwindSafe + Send {
    fn get_passphrase<W: io::Write>(&mut self, request: PassphraseRequest, out: W)
        -> Result<(), Error>;
}

impl<T: UnwindSafe + Send> PassphraseProvider for T
where T: FnMut(PassphraseRequest, &mut io::Write) -> Result<(), Error> {
    fn get_passphrase<W: io::Write>(&mut self, request: PassphraseRequest, mut out: W)
        -> Result<(), Error> {
        (*self)(request, &mut out)
    }
}

pub struct PassphraseProviderWrapper<P> {
    pub ctx: ffi::gpgme_ctx_t,
    pub old: (ffi::gpgme_passphrase_cb_t, *mut libc::c_void),
    pub state: Option<thread::Result<P>>,
}

impl<P> Drop for PassphraseProviderWrapper<P> {
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_set_passphrase_cb(self.ctx, self.old.0, self.old.1);
        }

        if let Some(Err(err)) = self.state.take() {
            panic::resume_unwind(err);
        }
    }
}

pub extern "C" fn passphrase_cb<P: PassphraseProvider>(hook: *mut libc::c_void,
    uid_hint: *const libc::c_char,
    info: *const libc::c_char,
    was_bad: libc::c_int, fd: libc::c_int)
    -> ffi::gpgme_error_t {
    let wrapper = unsafe { &mut *(hook as *mut PassphraseProviderWrapper<P>) };
    let mut provider = match wrapper.state.take() {
        Some(Ok(p)) => p,
        other => {
            wrapper.state = other;
            return ffi::GPG_ERR_GENERAL;
        }
    };

    match panic::catch_unwind(move || unsafe {
        let info = PassphraseRequest {
            uid_hint: uid_hint.as_ref().map(|s| CStr::from_ptr(s)),
            desc: info.as_ref().map(|s| CStr::from_ptr(s)),
            prev_attempt_failed: was_bad != 0,
        };
        let mut writer = FdWriter::new(fd);
        let result = provider.get_passphrase(info, &mut writer)
            .and_then(|_| writer.write_all(b"\n").map_err(Error::from))
            .err()
            .map_or(0, |err| err.raw());
        (provider, result)
    }) {
        Ok((provider, result)) => {
            wrapper.state = Some(Ok(provider));
            result
        }
        Err(err) => {
            wrapper.state = Some(Err(err));
            ffi::GPG_ERR_GENERAL
        }
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

pub trait ProgressHandler: UnwindSafe + Send {
    fn handle(&mut self, info: ProgressInfo);
}

impl<T: UnwindSafe + Send> ProgressHandler for T
    where T: FnMut(ProgressInfo) {
    fn handle(&mut self, info: ProgressInfo) {
        (*self)(info);
    }
}

pub struct ProgressHandlerWrapper<H> {
    pub ctx: ffi::gpgme_ctx_t,
    pub old: (ffi::gpgme_progress_cb_t, *mut libc::c_void),
    pub state: Option<thread::Result<H>>,
}

impl<H> Drop for ProgressHandlerWrapper<H> {
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_set_progress_cb(self.ctx, self.old.0, self.old.1);
        }

        if let Some(Err(err)) = self.state.take() {
            panic::resume_unwind(err);
        }
    }
}

pub extern "C" fn progress_cb<H: ProgressHandler>(hook: *mut libc::c_void,
    what: *const libc::c_char, typ: libc::c_int,
    current: libc::c_int, total: libc::c_int) {
    let wrapper = unsafe { &mut *(hook as *mut ProgressHandlerWrapper<H>) };
    let mut handler = match wrapper.state.take() {
        Some(Ok(handler)) => handler,
        other => {
            wrapper.state = other;
            return;
        }
    };

    match panic::catch_unwind(move || unsafe {
        let info = ProgressInfo {
            what: what.as_ref().map(|s| CStr::from_ptr(s)),
            typ: typ.into(),
            current: current.into(),
            total: total.into(),
        };
        handler.handle(info);
        handler
    }) {
        Ok(handler) => wrapper.state = Some(Ok(handler)),
        Err(err) => wrapper.state = Some(Err(err)),
    }
}

pub trait StatusHandler: UnwindSafe + Send {
    fn handle(&mut self, keyword: Option<&CStr>, args: Option<&CStr>) -> Result<(), Error>;
}

impl<T: UnwindSafe + Send> StatusHandler for T
where T: FnMut(Option<&CStr>, Option<&CStr>) -> Result<(), Error> {
    fn handle(&mut self, keyword: Option<&CStr>, args: Option<&CStr>) -> Result<(), Error> {
        (*self)(keyword, args)
    }
}

#[cfg(feature = "v1_6_0")]
pub struct StatusHandlerWrapper<H> {
    pub ctx: ffi::gpgme_ctx_t,
    pub old: (ffi::gpgme_status_cb_t, *mut libc::c_void),
    pub state: Option<thread::Result<H>>,
}

#[cfg(feature = "v1_6_0")]
impl<H> Drop for StatusHandlerWrapper<H> {
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_set_status_cb(self.ctx, self.old.0, self.old.1);
        }

        if let Some(Err(err)) = self.state.take() {
            panic::resume_unwind(err);
        }
    }
}

#[cfg(feature = "v1_6_0")]
pub extern "C" fn status_cb<H: StatusHandler>(hook: *mut libc::c_void,
    keyword: *const libc::c_char,
    args: *const libc::c_char)
    -> ffi::gpgme_error_t {
    let wrapper = unsafe { &mut *(hook as *mut StatusHandlerWrapper<H>) };
    let mut handler = match wrapper.state.take() {
        Some(Ok(handler)) => handler,
        other => {
            wrapper.state = other;
            return ffi::GPG_ERR_GENERAL;
        }
    };

    match panic::catch_unwind(move || unsafe {
        let keyword = keyword.as_ref().map(|s| CStr::from_ptr(s));
        let args = args.as_ref().map(|s| CStr::from_ptr(s));
        let result = handler.handle(args, keyword).err().map(|err| err.raw()).unwrap_or(0);
        (handler, result)
    }) {
        Ok((handler, result)) => {
            wrapper.state = Some(Ok(handler));
            result
        }
        Err(err) => {
            wrapper.state = Some(Err(err));
            ffi::GPG_ERR_GENERAL
        }
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

pub trait EditInteractor: UnwindSafe + Send {
    fn interact<W: io::Write>(&mut self, status: EditInteractionStatus, out: Option<W>)
        -> Result<(), Error>;
}

pub struct EditInteractorWrapper<'a, E> {
    pub state: Option<thread::Result<E>>,
    pub response: *mut Data<'a>,
}

impl<'a, E> Drop for EditInteractorWrapper<'a, E> {
    fn drop(&mut self) {
        if let Some(Err(err)) = self.state.take() {
            panic::resume_unwind(err);
        }
    }
}

pub extern "C" fn edit_cb<E: EditInteractor>(hook: *mut libc::c_void,
    status: ffi::gpgme_status_code_t,
    args: *const libc::c_char, fd: libc::c_int)
    -> ffi::gpgme_error_t {
    let wrapper = unsafe { &mut *(hook as *mut EditInteractorWrapper<E>) };
    let response = wrapper.response;
    let mut interactor = match wrapper.state.take() {
        Some(Ok(interactor)) => interactor,
        other => {
            wrapper.state = other;
            return ffi::GPG_ERR_GENERAL;
        }
    };

    match panic::catch_unwind(move || unsafe {
        let status = EditInteractionStatus {
            code: edit::StatusCode::from_raw(status),
            args: args.as_ref().map(|s| CStr::from_ptr(s)),
            response: &mut *response,
        };
        let result = if fd < 0 {
            interactor.interact(status, None::<&mut io::Write>)
        } else {
            interactor.interact(status, Some(FdWriter::new(fd)))
        }.err().map(|err| err.raw()).unwrap_or(0);
        (interactor, result)
    }) {
        Ok((interactor, result)) => {
            wrapper.state = Some(Ok(interactor));
            result
        }
        Err(err) => {
            wrapper.state = Some(Err(err));
            ffi::GPG_ERR_GENERAL
        }
    }
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

pub trait Interactor: 'static + Send {
    fn interact<W: io::Write>(&mut self, status: InteractionStatus, out: Option<W>)
        -> Result<(), Error>;
}

#[cfg(feature = "v1_7_0")]
pub struct InteractorWrapper<'a, I> {
    pub state: Option<thread::Result<I>>,
    pub response: *mut Data<'a>,
}

#[cfg(feature = "v1_7_0")]
impl<'a, I> Drop for InteractorWrapper<'a, I> {
    fn drop(&mut self) {
        if let Some(Err(err)) = self.state.take() {
            panic::resume_unwind(err);
        }
    }
}

#[cfg(feature = "v1_7_0")]
pub extern "C" fn interact_cb<H: InteractHandler>(hook: *mut libc::c_void,
    keyword: *const libc::c_char,
    args: *const libc::c_char, fd: libc::c_int)
    -> ffi::gpgme_error_t {
    let wrapper = unsafe { &mut *(hook as *mut EditInteractorWrapper<E>) };
    let response = wrapper.response;
    let mut interactor = match wrapper.state.take() {
        Some(Ok(interactor)) => interactor,
        other => {
            wrapper.state = other;
            return ffi::GPG_ERR_GENERAL;
        }
    };

    match panic::catch_unwind(move || unsafe {
        let status = EditInteractionStatus {
            keyword: keyword.as_ref().map(|s| CStr::from_ptr(s)),
            args: args.as_ref().map(|s| CStr::from_ptr(s)),
            response: &mut *response,
        };
        let result = if fd < 0 {
            interactor.interact(status, None::<&mut io::Write>)
        } else {
            interactor.interact(status, Some(FdWriter::new(fd)))
        }.err().map(|err| err.raw()).unwrap_or(0);
        (interactor, result)
    }) {
        Ok((interactor, result)) => {
            wrapper.state = Some(Ok(interactor));
            result
        }
        Err(err) => {
            wrapper.state = Some(Err(err));
            ffi::GPG_ERR_GENERAL
        }
    }
}
