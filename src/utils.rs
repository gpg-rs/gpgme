use std::ffi::CStr;
use std::io;
use std::io::prelude::*;
use std::str;

use libc;

use gpgme_sys as sys;

use error::Error;

macro_rules! try_opt {
    ($e:expr) => (match $e { Some(v) => v, None => return None });
}

macro_rules! return_err {
    ($e:expr) => (match $e {
        $crate::error::GPG_ERR_NO_ERROR => (),
        err => return Err($crate::Error::new(err)),
    });
}

macro_rules! list_iterator {
    ($item:ty, $constructor:path) => {
        type Item = $item;

        fn next(&mut self) -> Option<Self::Item> {
            let current = self.current;
            if !current.is_null() {
                unsafe {
                    self.current = (*current).next;
                    Some($constructor(current))
                }
            } else {
                None
            }
        }
    };
    ($item:ty) => (list_iterator!($item, $item::from_raw));
}

pub unsafe fn from_cstr<'a>(s: *const libc::c_char) -> Option<&'a str> {
    if !s.is_null() {
        str::from_utf8(CStr::from_ptr(s).to_bytes()).ok()
    } else {
        None
    }
}

pub struct FdWriter {
    fd: libc::c_int,
}

impl FdWriter {
    pub fn new(fd: libc::c_int) -> FdWriter {
        FdWriter { fd: fd }
    }
}

impl Write for FdWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let result = unsafe {
            sys::gpgme_io_write(self.fd, buf.as_ptr() as *const _,
                                buf.len() as libc::size_t)
        };
        if result >= 0 {
            Ok(result as usize)
        } else {
            Err(Error::last_os_error().into())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
