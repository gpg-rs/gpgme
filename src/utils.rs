use std::error;
use std::ffi::CStr;
use std::fmt;
use std::io;
use std::io::prelude::*;
use std::str::Utf8Error;

use libc;
use ffi;

use error::Error;

macro_rules! try_opt {
    ($e:expr) => (match $e { Some(v) => v, None => return None });
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

macro_rules! ffi_enum_wrapper {
    ($(#[$Attr:meta])* pub enum $Name:ident: $T:ty {
        $($(#[$ItemAttr:meta])* $Item:ident = $Value:expr),+
    }) => {
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
        $(#[$Attr])*
        pub struct $Name($T);

        $(pub const $Item: $Name = $Name($Value as $T);)+

        impl $Name {
            pub unsafe fn from_raw(raw: $T) -> $Name {
                $Name(raw)
            }

            pub fn raw(&self) -> $T {
                self.0
            }
        }
    };
    ($(#[$Attr:meta])* pub enum $Name:ident: $T:ty {
        $($(#[$ItemAttr:meta])* $Item:ident = $Value:expr,)+
    }) => {
        ffi_enum_wrapper! {
            $(#[$Attr])*
            pub enum $Name: $T {
                $($(#[$ItemAttr])* $Item = $Value),+
            }
        }
    };
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum StrError<'a> {
    NotPresent,
    NotUtf8(&'a CStr, Utf8Error),
}

pub type StrResult<'a> = Result<&'a str, StrError<'a>>;

impl<'a> fmt::Display for StrError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StrError::NotPresent => write!(f, "no string present"),
            StrError::NotUtf8(ref s, _) => {
                write!(f, "string was not valid utf-8: {:?}", s)
            }
        }
    }
}

impl<'a> error::Error for StrError<'a> {
    fn description(&self) -> &str {
        match *self {
            StrError::NotPresent => "no string present",
            StrError::NotUtf8(..) => "string was not valid utf-8",
        }
    }
}

pub unsafe fn from_cstr<'a>(s: *const libc::c_char) -> StrResult<'a> {
    if !s.is_null() {
        let s = CStr::from_ptr(s);
        s.to_str().map_err(|e| StrError::NotUtf8(s, e))
    } else {
        Err(StrError::NotPresent)
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
            ffi::gpgme_io_write(self.fd, buf.as_ptr() as *const _, buf.len() as libc::size_t)
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
