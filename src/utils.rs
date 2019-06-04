use std::io::{self, prelude::*};

use ffi;
use libc;

use crate::Error;

pub use cstr_argument::CStrArgument;
pub type SmallVec<T> = ::smallvec::SmallVec<[T; 4]>;

macro_rules! impl_list_iterator {
    ($Vis:vis struct $Name:ident($Item:ident: $Raw:ty)) => {
        #[derive(Clone)]
        $Vis struct $Name<'a>(Option<$Item<'a>>);

        impl<'a> $Name<'a> {
            #[inline]
            pub unsafe fn from_list(first: $Raw) -> Self {
                $Name(first.as_mut().map(|r| $Item::from_raw(r)))
            }
        }

        impl<'a> Iterator for $Name<'a> {
            type Item = $Item<'a>;

            #[inline]
            fn next(&mut self) -> Option<Self::Item> {
                unsafe {
                    self.0.take().map(|c| {
                        self.0 = (*c.as_raw()).next.as_mut().map(|r| $Item::from_raw(r));
                        c
                    })
                }
            }
        }

        impl<'a> ::std::iter::FusedIterator for $Name<'a> {}

        impl<'a> ::std::fmt::Debug for $Name<'a> {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
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
    ($(#[$Attr:meta])* $Vis:vis enum $Name:ident($Default:ident): $T:ty {
        $($(#[$ItemAttr:meta])* $Item:ident = $Value:expr),+
    }) => {
        #[derive(Copy, Clone, Eq, PartialEq, Hash)]
        $(#[$Attr])*
        $Vis enum $Name {
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
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                match *self {
                    $($Name::$Item => {
                        write!(f, concat!(stringify!($Name), "::",
                                          stringify!($Item), "({:?})"), self.raw())
                    })+
                }
            }
        }
    };
    ($(#[$Attr:meta])* $Vis:vis enum $Name:ident($Default:ident): $T:ty {
        $($(#[$ItemAttr:meta])* $Item:ident = $Value:expr,)+
    }) => {
        ffi_enum_wrapper! {
            $(#[$Attr])*
            $Vis enum $Name($Default): $T {
                $($(#[$ItemAttr])* $Item = $Value),+
            }
        }
    };
    ($(#[$Attr:meta])* $Vis:vis enum $Name:ident: $T:ty {
        $($(#[$ItemAttr:meta])* $Item:ident = $Value:expr),+
    }) => {
        #[derive(Copy, Clone, Eq, PartialEq, Hash)]
        $(#[$Attr])*
        $Vis enum $Name {
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
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
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
    ($(#[$Attr:meta])* $Vis:vis enum $Name:ident: $T:ty {
        $($(#[$ItemAttr:meta])* $Item:ident = $Value:expr,)+
    }) => {
        ffi_enum_wrapper! {
            $(#[$Attr])*
            $Vis enum $Name: $T {
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
        Self { fd }
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
