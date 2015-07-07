use std::ffi::CStr;
use std::io;
use std::io::prelude::*;
use std::str;

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

macro_rules! enum_wrapper {
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
        enum_wrapper! {
            $(#[$Attr])*
            pub enum $Name: $T {
                $($(#[$ItemAttr])* $Item = $Value),+
            }
        }
    };
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
            ffi::gpgme_io_write(self.fd, buf.as_ptr() as *const _,
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
