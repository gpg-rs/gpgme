use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::io;
use std::io::prelude::*;

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
            unsafe {
                self.current.as_mut().map(|c| {
                    self.current = c.next;
                    $constructor(c)
                })
            }
        }
    };
    ($item:ty) => (list_iterator!($item, $item::from_raw));
}

macro_rules! ffi_enum_wrapper {
    ($(#[$Attr:meta])* pub enum $Name:ident: $T:ty {
        $($(#[$ItemAttr:meta])* $Item:ident = $Value:expr),+
    }) => {
        #[derive(Copy, Clone, Eq, PartialEq, Hash)]
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

        impl ::std::fmt::Debug for $Name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                match *self {
                    $($Item => write!(f, concat!(stringify!($Item), "({:?})"), self.0),)+
                    _ => write!(f, concat!(stringify!($Name), "({:?})"), self.0),
                }
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

macro_rules! impl_wrapper {
    ($Name:ident: $T:ty) => {
        impl $Name {
            pub unsafe fn from_raw(raw: $T) -> Self {
                $Name(raw)
            }

            pub fn as_raw(&self) -> $T {
                self.0
            }

            pub fn into_raw(self) -> $T {
                let raw = self.0;
                ::std::mem::forget(self);
                raw
            }
        }
    }
}

pub trait IntoNativeString {
    type Output: AsRef<CStr>;

    fn into_native(self) -> Self::Output;
}

impl<'a> IntoNativeString for CString {
    type Output = Self;

    fn into_native(self) -> Self {
        self
    }
}

impl<'a> IntoNativeString for &'a CString {
    type Output = &'a CStr;

    fn into_native(self) -> Self::Output {
        self
    }
}

impl<'a> IntoNativeString for &'a CStr {
    type Output = Self;

    fn into_native(self) -> Self {
        self
    }
}

impl<'a> IntoNativeString for String {
    type Output = CString;

    fn into_native(self) -> Self::Output {
        self.into_bytes().into_native()
    }
}

impl<'a> IntoNativeString for &'a String {
    type Output = Cow<'a, CStr>;

    fn into_native(self) -> Self::Output {
        self.as_str().into_native()
    }
}

impl<'a> IntoNativeString for &'a str {
    type Output = Cow<'a, CStr>;

    fn into_native(self) -> Self::Output {
        self.as_bytes().into_native()
    }
}

impl<'a> IntoNativeString for Vec<u8> {
    type Output = CString;

    fn into_native(mut self) -> Self::Output {
        if let Some(term) = self.iter().position(|&x| x == 0) {
            self.truncate(term);
        }

        unsafe {
            CString::from_vec_unchecked(self)
        }
    }
}

impl<'a> IntoNativeString for &'a Vec<u8> {
    type Output = Cow<'a, CStr>;

    fn into_native(self) -> Self::Output {
        self.as_slice().into_native()
    }
}

impl<'a> IntoNativeString for &'a [u8] {
    type Output = Cow<'a, CStr>;

    fn into_native(self) -> Self::Output {
        unsafe {
            if let Some(term) = self.iter().position(|&x| x == 0) {
                Cow::Borrowed(CStr::from_bytes_with_nul_unchecked(&self[..term]))
            } else {
                Cow::Owned(CString::from_vec_unchecked(self.into()))
            }
        }
    }
}

pub struct FdWriter {
    fd: libc::c_int,
}

impl FdWriter {
    pub unsafe fn new(fd: libc::c_int) -> FdWriter {
        FdWriter { fd: fd }
    }
}

impl Write for FdWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let result = unsafe {
            ffi::gpgme_io_write(self.fd, buf.as_ptr() as *const _, buf.len().into())
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
