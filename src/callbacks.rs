use std::ffi::CStr;
use std::io;
use std::str::Utf8Error;

use libc;
use ffi;

use {Data, Error};
use edit;
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

pub trait PassphraseProvider: Send {
    fn get_passphrase<W: io::Write>(&mut self, request: PassphraseRequest, out: W)
        -> Result<(), Error>;
}

impl<T: Send> PassphraseProvider for T
where T: FnMut(PassphraseRequest, &mut io::Write) -> Result<(), Error> {
    fn get_passphrase<W: io::Write>(&mut self, request: PassphraseRequest, mut out: W)
        -> Result<(), Error> {
        (*self)(request, &mut out)
    }
}

pub struct PassphraseProviderGuard {
    pub ctx: ffi::gpgme_ctx_t,
    pub old: (ffi::gpgme_passphrase_cb_t, *mut libc::c_void),
}

impl Drop for PassphraseProviderGuard {
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_set_passphrase_cb(self.ctx, self.old.0, self.old.1);
        }
    }
}

pub extern "C" fn passphrase_cb<P: PassphraseProvider>(hook: *mut libc::c_void,
    uid_hint: *const libc::c_char,
    info: *const libc::c_char,
    was_bad: libc::c_int, fd: libc::c_int)
    -> ffi::gpgme_error_t {
    use std::io::prelude::*;

    let provider = hook as *mut P;
    unsafe {
        let info = PassphraseRequest {
            uid_hint: uid_hint.as_ref().map(|s| CStr::from_ptr(s)),
            desc: info.as_ref().map(|s| CStr::from_ptr(s)),
            prev_attempt_failed: was_bad != 0,
        };
        let mut writer = FdWriter::new(fd);
        (*provider)
            .get_passphrase(info, &mut writer)
            .and_then(|_| writer.write_all(b"\n").map_err(Error::from))
            .err()
            .map_or(0, |err| err.raw())
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
    pub ctx: ffi::gpgme_ctx_t,
    pub old: (ffi::gpgme_progress_cb_t, *mut libc::c_void),
}

impl Drop for ProgressHandlerGuard {
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_set_progress_cb(self.ctx, self.old.0, self.old.1);
        }
    }
}

pub extern "C" fn progress_cb<H: ProgressHandler>(hook: *mut libc::c_void,
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

#[cfg(feature = "v1_6_0")]
pub struct StatusHandlerGuard {
    pub ctx: ffi::gpgme_ctx_t,
    pub old: (ffi::gpgme_status_cb_t, *mut libc::c_void),
}

#[cfg(feature = "v1_6_0")]
impl Drop for StatusHandlerGuard {
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_set_status_cb(self.ctx, self.old.0, self.old.1);
        }
    }
}

pub trait StatusHandler: 'static + Send {
    fn handle(&mut self, keyword: Option<&CStr>, args: Option<&CStr>) -> Result<(), Error>;
}

impl<T: 'static + Send> StatusHandler for T
where T: FnMut(Option<&CStr>, Option<&CStr>) -> Result<(), Error> {
    fn handle(&mut self, keyword: Option<&CStr>, args: Option<&CStr>) -> Result<(), Error> {
        (*self)(keyword, args)
    }
}

#[cfg(feature = "v1_6_0")]
pub extern "C" fn status_cb<H: StatusHandler>(hook: *mut libc::c_void,
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

#[derive(Debug)]
pub struct EditStatus<'a> {
    pub code: edit::StatusCode,
    args: Option<&'a CStr>,
    pub response: &'a mut Data<'a>,
}

impl<'a> EditStatus<'a> {
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

pub trait EditHandler: 'static + Send {
    fn handle<W: io::Write>(&mut self, status: EditStatus, out: Option<W>) -> Result<(), Error>;
}

pub struct EditHandlerWrapper<'a, E: EditHandler> {
    pub handler: E,
    pub response: *mut Data<'a>,
}

pub extern "C" fn edit_cb<E: EditHandler>(hook: *mut libc::c_void,
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

#[derive(Debug)]
pub struct InteractStatus<'a> {
    keyword: Option<&'a CStr>,
    args: Option<&'a CStr>,
    pub response: &'a mut Data<'a>,
}

impl<'a> InteractStatus<'a> {
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

pub trait InteractHandler: 'static + Send {
    fn handle<W: io::Write>(&mut self, status: InteractStatus, out: Option<W>)
        -> Result<(), Error>;
}

#[cfg(feature = "v1_7_0")]
pub struct InteractHandlerWrapper<'a, H: InteractHandler> {
    pub handler: H,
    pub response: *mut Data<'a>,
}

#[cfg(feature = "v1_7_0")]
pub extern "C" fn interact_cb<H: InteractHandler>(hook: *mut libc::c_void,
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
