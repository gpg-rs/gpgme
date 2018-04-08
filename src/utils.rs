use std::io;
use std::io::prelude::*;

use ffi;
use libc;

use Error;

pub use cstr_argument::CStrArgument;

pub type SmallVec<T> = ::smallvec::SmallVec<[T; 4]>;

include!(concat!(env!("OUT_DIR"), "/version.rs"));

macro_rules! count_list {
    ($list:expr) => {
        (|| {
            let mut count = 0usize;
            let mut current = $list;
            while !current.is_null() {
                count = count.checked_add(1)?;
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
                        self.left = self.left.map(|x| x.saturating_sub(1));
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
    ($Name:ident($T:ty)$(, $Args:expr)*) => {
        #[inline]
        pub unsafe fn from_raw(raw: $T) -> Self {
            $Name(NonNull::<$T>::new(raw).unwrap()$(, $Args)*)
        }

        #[inline]
        pub fn as_raw(&self) -> $T {
            self.0.as_ptr()
        }

        #[inline]
        pub fn into_raw(self) -> $T {
            let raw = self.as_raw();
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

pub(crate) trait Ptr {
    type Inner;
}

impl<T> Ptr for *mut T {
    type Inner = T;
}

impl<T> Ptr for *const T {
    type Inner = T;
}
