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

macro_rules! count_list {
    ($list:expr) => {
        (|| {
            let mut count = 0usize;
            let mut current = $list;
            while !current.is_null() {
                count = try_opt!(count.checked_add(1));
                current = (*current).next;
            }
            Some(count)
        })()
    };
}

macro_rules! impl_list_iterator {
    ($Name:ident, $Item:ident, $Raw:ty) => {
        #[derive(Clone)]
        pub struct $Name<'a> {
            current: Option<$Item<'a>>,
            left: Option<usize>,
        }

        impl<'a> $Name<'a> {
            #[inline]
            pub unsafe fn from_list(first: $Raw) -> Self {
                $Name {
                    current: first.as_mut().map(|r| $Item::from_raw(r)),
                    left: count_list!(first),
                }
            }
        }

        impl<'a> Iterator for $Name<'a> {
            type Item = $Item<'a>;

            #[inline]
            fn next(&mut self) -> Option<Self::Item> {
                unsafe {
                    self.current.take().map(|c| {
                        self.current = (*c.as_raw()).next.as_mut().map(|r| $Item::from_raw(r));
                        self.left = self.left.and_then(|x| x.checked_sub(1));
                        c
                    })
                }
            }

            #[inline]
            fn size_hint(&self) -> (usize, Option<usize>) {
                (self.left.unwrap_or(usize::max_value()), self.left)
            }
        }

        impl<'a> ::std::fmt::Debug for $Name<'a> {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                f.debug_list().entries(self.clone()).finish()
            }
        }
    };
}

macro_rules! impl_wrapper {
    (@phantom $Name:ident: $T:ty) => {
        #[inline]
        pub unsafe fn from_raw(raw: $T) -> Self {
            debug_assert!(!raw.is_null());
            $Name(NonZero::new(raw), PhantomData)
        }

        #[inline]
        pub fn as_raw(&self) -> $T {
            self.0.get()
        }
    };
    ($Name:ident: $T:ty) => {
        #[inline]
        pub unsafe fn from_raw(raw: $T) -> Self {
            debug_assert!(!raw.is_null());
            $Name(NonZero::new(raw))
        }

        #[inline]
        pub fn as_raw(&self) -> $T {
            self.0.get()
        }

        #[inline]
        pub fn into_raw(self) -> $T {
            let raw = self.0.get();
            ::std::mem::forget(self);
            raw
        }
    };
}

macro_rules! ffi_enum_wrapper {
    ($(#[$Attr:meta])* pub enum $Name:ident($Default:ident): $T:ty {
        $($(#[$ItemAttr:meta])* $Item:ident = $Value:expr),+
    }) => {
        #[derive(Copy, Clone, Eq, PartialEq, Hash)]
        $(#[$Attr])*
        pub enum $Name {
            $($(#[$ItemAttr])* $Item,)+
        }

        impl $Name {
            #[inline]
            pub unsafe fn from_raw(raw: $T) -> $Name {
                $(if raw == $Value {
                    $Name::$Item
                } else )+ {
                    $Name::$Default
                }
            }

            #[inline]
            pub fn raw(&self) -> $T {
                match *self {
                    $($Name::$Item => $Value,)+
                }
            }
        }

        impl ::std::fmt::Debug for $Name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                match *self {
                    $($Name::$Item => {
                        write!(f, concat!(stringify!($Name), "::",
                                          stringify!($Item), "({:?})"), self.raw())
                    })+
                }
            }
        }
    };
    ($(#[$Attr:meta])* pub enum $Name:ident($Default:ident): $T:ty {
        $($(#[$ItemAttr:meta])* $Item:ident = $Value:expr,)+
    }) => {
        ffi_enum_wrapper! {
            $(#[$Attr])*
            pub enum $Name($Default): $T {
                $($(#[$ItemAttr])* $Item = $Value),+
            }
        }
    };
    ($(#[$Attr:meta])* pub enum $Name:ident: $T:ty {
        $($(#[$ItemAttr:meta])* $Item:ident = $Value:expr),+
    }) => {
        #[derive(Copy, Clone, Eq, PartialEq, Hash)]
        $(#[$Attr])*
        pub enum $Name {
            $($(#[$ItemAttr])* $Item,)+
            Other($T),
        }

        impl $Name {
            #[inline]
            pub unsafe fn from_raw(raw: $T) -> $Name {
                $(if raw == $Value {
                    $Name::$Item
                } else )+ {
                    $Name::Other(raw)
                }
            }

            #[inline]
            pub fn raw(&self) -> $T {
                match *self {
                    $($Name::$Item => $Value,)+
                    $Name::Other(other) => other,
                }
            }
        }

        impl ::std::fmt::Debug for $Name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                match *self {
                    $($Name::$Item => {
                        write!(f, concat!(stringify!($Name), "::",
                                          stringify!($Item), "({:?})"), self.raw())
                    })+
                    _ => write!(f, concat!(stringify!($Name), "({:?})"), self.raw()),
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

        unsafe { CString::from_vec_unchecked(self) }
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
        let result =
            unsafe { ffi::gpgme_io_write(self.fd, buf.as_ptr() as *const _, buf.len().into()) };
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

cfg_if! {
    if #[cfg(any(nightly, feature = "nightly"))] {
        pub use core::nonzero::NonZero;
        // use core::nonzero::{self, Zeroable};
        //
        // #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
        // pub struct NonZero<T: Zeroable>(nonzero::NonZero<T>);
        //
        // impl<T: Zeroable> NonZero<T> {
        //     #[inline(always)]
        //     pub unsafe fn new(inner: T) -> NonZero<T> {
        //         NonZero(nonzero::NonZero::new(inner))
        //     }
        //
        //     pub fn get(&self) -> &T {
        //         &*self.0
        //     }
        // }
    } else {
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct NonZero<T>(T);

        impl<T> NonZero<T> {
            #[inline(always)]
            pub unsafe fn new(inner: T) -> NonZero<T> {
                NonZero(inner)
            }

            pub fn get(self) -> T {
                self.0
            }
        }
    }
}
