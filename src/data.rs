use std::borrow::BorrowMut;
use std::ffi::CStr;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::marker::PhantomData;
use std::mem;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::ptr;
use std::result;
use std::slice;
use std::str::Utf8Error;

use libc;
use conv::{UnwrapOrSaturate, ValueInto};
use ffi;

use {IntoNativeString, NonZero};
use error::{self, Error, Result};

ffi_enum_wrapper! {
    pub enum Encoding: ffi::gpgme_data_encoding_t {
        None = ffi::GPGME_DATA_ENCODING_NONE,
        Binary = ffi::GPGME_DATA_ENCODING_BINARY,
        Base64 = ffi::GPGME_DATA_ENCODING_BASE64,
        Armor = ffi::GPGME_DATA_ENCODING_ARMOR,
        Url = ffi::GPGME_DATA_ENCODING_URL,
        UrlEscaped = ffi::GPGME_DATA_ENCODING_URLESC,
        Url0 = ffi::GPGME_DATA_ENCODING_URL0,
        Mime = ffi::GPGME_DATA_ENCODING_MIME,
    }
}

ffi_enum_wrapper! {
    pub enum Type: ffi::gpgme_data_type_t {
        Unknown = ffi::GPGME_DATA_TYPE_UNKNOWN,
        Invalid = ffi::GPGME_DATA_TYPE_INVALID,
        PgpSigned = ffi::GPGME_DATA_TYPE_PGP_SIGNED,
        PgpEncrypted = ffi::GPGME_DATA_TYPE_PGP_ENCRYPTED,
        PgpOther = ffi::GPGME_DATA_TYPE_PGP_OTHER,
        PgpKey = ffi::GPGME_DATA_TYPE_PGP_KEY,
        PgpSignature = ffi::GPGME_DATA_TYPE_PGP_SIGNATURE,
        CmsSigned = ffi::GPGME_DATA_TYPE_CMS_SIGNED,
        CmsEncrypted = ffi::GPGME_DATA_TYPE_CMS_ENCRYPTED,
        CmsOther = ffi::GPGME_DATA_TYPE_CMS_OTHER,
        X509Certificate = ffi::GPGME_DATA_TYPE_X509_CERT,
        Pkcs12 = ffi::GPGME_DATA_TYPE_PKCS12,
    }
}

struct CallbackWrapper<S> {
    cbs: ffi::gpgme_data_cbs,
    inner: S,
}

#[derive(Clone)]
pub struct WrappedError<S>(Error, S);

impl<S> WrappedError<S> {
    pub fn error(&self) -> Error {
        self.0
    }

    pub fn into_inner(self) -> S {
        self.1
    }
}

impl<S> fmt::Debug for WrappedError<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S> fmt::Display for WrappedError<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, fmt)
    }
}

#[derive(Debug)]
pub struct Data<'a>(NonZero<ffi::gpgme_data_t>, PhantomData<&'a ()>);

unsafe impl<'a> Send for Data<'a> {}

impl<'a> Drop for Data<'a> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_data_release(self.as_raw());
        }
    }
}

impl<'a> Data<'a> {
    #[inline]
    pub unsafe fn from_raw(raw: ffi::gpgme_data_t) -> Self {
        debug_assert!(!raw.is_null());
        Data(NonZero::new(raw), PhantomData)
    }

    #[inline]
    pub fn as_raw(&self) -> ffi::gpgme_data_t {
        self.0.get()
    }

    #[inline]
    pub fn into_raw(self) -> ffi::gpgme_data_t {
        let raw = self.0.get();
        mem::forget(self);
        raw
    }

    #[inline]
    pub fn stdin() -> Result<Data<'static>> {
        Data::from_reader(io::stdin()).map_err(|err| err.error())
    }

    #[inline]
    pub fn stdout() -> Result<Data<'static>> {
        Data::from_writer(io::stdout()).map_err(|err| err.error())
    }

    #[inline]
    pub fn stderr() -> Result<Data<'static>> {
        Data::from_writer(io::stderr()).map_err(|err| err.error())
    }

    /// Constructs an empty data object.
    #[inline]
    pub fn new() -> Result<Data<'static>> {
        unsafe {
            let mut data = ptr::null_mut();
            return_err!(ffi::gpgme_data_new(&mut data));
            Ok(Data::from_raw(data))
        }
    }

    /// Constructs a data object and fills it with the contents of the file
    /// referenced by `path`.
    #[inline]
    pub fn load<P: IntoNativeString>(path: P) -> Result<Data<'static>> {
        let path = path.into_native();
        unsafe {
            let mut data = ptr::null_mut();
            return_err!(ffi::gpgme_data_new_from_file(
                &mut data,
                path.as_ref().as_ptr(),
                1,
            ));
            Ok(Data::from_raw(data))
        }
    }

    /// Constructs a data object and fills it with a copy of `bytes`.
    #[inline]
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Data<'static>> {
        let bytes = bytes.as_ref();
        let mut data = unsafe {
            let (buf, len) = (bytes.as_ptr() as *const _, bytes.len().into());
            let mut data = ptr::null_mut();
            return_err!(ffi::gpgme_data_new_from_mem(&mut data, buf, len, 1));
            Data::from_raw(data)
        };
        let _ = data.set_flag("size-hint", bytes.len().to_string());
        Ok(data)
    }

    /// Constructs a data object which copies from `buf` as needed.
    #[inline]
    pub fn from_buffer<B: AsRef<[u8]> + ?Sized>(buf: &B) -> Result<Data> {
        let buf = buf.as_ref();
        let mut data = unsafe {
            let (buf, len) = (buf.as_ptr() as *const _, buf.len().into());
            let mut data = ptr::null_mut();
            return_err!(ffi::gpgme_data_new_from_mem(&mut data, buf, len, 0));
            Data::from_raw(data)
        };
        let _ = data.set_flag("size-hint", buf.len().to_string());
        Ok(data)
    }

    #[inline]
    #[cfg(unix)]
    pub fn from_fd<T: AsRawFd + ?Sized>(file: &T) -> Result<Data> {
        unsafe {
            let mut data = ptr::null_mut();
            return_err!(ffi::gpgme_data_new_from_fd(&mut data, file.as_raw_fd()));
            Ok(Data::from_raw(data))
        }
    }

    #[inline]
    pub unsafe fn from_raw_file(file: *mut libc::FILE) -> Result<Self> {
        let mut data = ptr::null_mut();
        return_err!(ffi::gpgme_data_new_from_stream(&mut data, file));
        Ok(Data::from_raw(data))
    }

    unsafe fn from_callbacks<S>(cbs: ffi::gpgme_data_cbs, src: S)
        -> result::Result<Self, WrappedError<S>>
    where
        S: Send + 'a, {
        let src = Box::into_raw(Box::new(CallbackWrapper {
            cbs: cbs,
            inner: src,
        }));
        let cbs = &mut (*src).cbs as *mut _;
        let mut data = ptr::null_mut();
        let result = ffi::gpgme_data_new_from_cbs(&mut data, cbs, src as *mut _);
        if result == 0 {
            Ok(Data::from_raw(data))
        } else {
            Err(WrappedError(Error::new(result), Box::from_raw(src).inner))
        }
    }

    #[inline]
    pub fn from_reader<R>(r: R) -> result::Result<Self, WrappedError<R>>
    where
        R: Read + Send + 'a, {
        let cbs = ffi::gpgme_data_cbs {
            read: Some(read_callback::<R>),
            write: None,
            seek: None,
            release: Some(release_callback::<R>),
        };
        unsafe { Data::from_callbacks(cbs, r) }
    }

    #[inline]
    pub fn from_seekable_reader<R>(r: R) -> result::Result<Self, WrappedError<R>>
    where
        R: Read + Seek + Send + 'a, {
        let cbs = ffi::gpgme_data_cbs {
            read: Some(read_callback::<R>),
            write: None,
            seek: Some(seek_callback::<R>),
            release: Some(release_callback::<R>),
        };
        unsafe { Data::from_callbacks(cbs, r) }
    }

    #[inline]
    pub fn from_writer<W>(w: W) -> result::Result<Self, WrappedError<W>>
    where
        W: Write + Send + 'a, {
        let cbs = ffi::gpgme_data_cbs {
            read: None,
            write: Some(write_callback::<W>),
            seek: None,
            release: Some(release_callback::<W>),
        };
        unsafe { Data::from_callbacks(cbs, w) }
    }

    #[inline]
    pub fn from_seekable_writer<W>(w: W) -> result::Result<Self, WrappedError<W>>
    where
        W: Write + Seek + Send + 'a, {
        let cbs = ffi::gpgme_data_cbs {
            read: None,
            write: Some(write_callback::<W>),
            seek: Some(seek_callback::<W>),
            release: Some(release_callback::<W>),
        };
        unsafe { Data::from_callbacks(cbs, w) }
    }

    #[inline]
    pub fn from_stream<S: Send>(s: S) -> result::Result<Self, WrappedError<S>>
    where
        S: Read + Write + Send + 'a, {
        let cbs = ffi::gpgme_data_cbs {
            read: Some(read_callback::<S>),
            write: Some(write_callback::<S>),
            seek: None,
            release: Some(release_callback::<S>),
        };
        unsafe { Data::from_callbacks(cbs, s) }
    }

    #[inline]
    pub fn from_seekable_stream<S>(s: S) -> result::Result<Self, WrappedError<S>>
    where
        S: Read + Write + Seek + Send + 'a, {
        let cbs = ffi::gpgme_data_cbs {
            read: Some(read_callback::<S>),
            write: Some(write_callback::<S>),
            seek: Some(seek_callback::<S>),
            release: Some(release_callback::<S>),
        };
        unsafe { Data::from_callbacks(cbs, s) }
    }

    #[inline]
    pub fn filename(&self) -> result::Result<&str, Option<Utf8Error>> {
        self.filename_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn filename_raw(&self) -> Option<&CStr> {
        unsafe {
            ffi::gpgme_data_get_file_name(self.as_raw())
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn clear_filename(&mut self) -> Result<()> {
        unsafe {
            return_err!(ffi::gpgme_data_set_file_name(self.as_raw(), ptr::null()));
        }
        Ok(())
    }

    #[inline]
    pub fn set_filename<S: IntoNativeString>(&mut self, name: S) -> Result<()> {
        let name = name.into_native();
        unsafe {
            return_err!(ffi::gpgme_data_set_file_name(
                self.as_raw(),
                name.as_ref().as_ptr(),
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn encoding(&self) -> Encoding {
        unsafe { Encoding::from_raw(ffi::gpgme_data_get_encoding(self.as_raw())) }
    }

    #[inline]
    pub fn set_encoding(&mut self, enc: Encoding) -> Result<()> {
        unsafe { return_err!(ffi::gpgme_data_set_encoding(self.as_raw(), enc.raw())) }
        Ok(())
    }

    #[inline]
    #[cfg(feature = "v1_7_0")]
    pub fn set_flag<S1, S2>(&mut self, name: S1, value: S2) -> Result<()>
    where
        S1: IntoNativeString,
        S2: IntoNativeString, {
        let name = name.into_native();
        let value = value.into_native();
        unsafe {
            return_err!(ffi::gpgme_data_set_flag(
                self.as_raw(),
                name.as_ref().as_ptr(),
                value.as_ref().as_ptr(),
            ));
        }
        Ok(())
    }

    #[inline]
    #[cfg(not(feature = "v1_7_0"))]
    pub fn set_flag<S1, S2>(&mut self, _name: S1, _value: S2) -> Result<()>
    where
        S1: IntoNativeString,
        S2: IntoNativeString, {
        Err(Error::new(error::GPG_ERR_NOT_SUPPORTED))
    }

    #[inline]
    #[cfg(feature = "v1_4_3")]
    pub fn identify(&mut self) -> Type {
        unsafe { Type::from_raw(ffi::gpgme_data_identify(self.as_raw(), 0)) }
    }

    #[inline]
    #[cfg(not(feature = "v1_4_3"))]
    pub fn identify(&mut self) -> Type {
        Type::Unknown
    }

    #[inline]
    pub fn try_into_bytes(self) -> Option<Vec<u8>> {
        unsafe {
            let mut len = 0;
            ffi::gpgme_data_release_and_get_mem(self.into_raw(), &mut len)
                .as_ref()
                .map(|b| {
                    slice::from_raw_parts(b as *const _ as *const _, len).to_vec()
                })
        }
    }
}

impl<'a> Read for Data<'a> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = unsafe {
            let (buf, len) = (buf.as_mut_ptr() as *mut _, buf.len());
            ffi::gpgme_data_read(self.as_raw(), buf, len)
        };
        if result >= 0 {
            Ok(result as usize)
        } else {
            Err(Error::last_os_error().into())
        }
    }
}

impl<'a> Write for Data<'a> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let result = unsafe {
            let (buf, len) = (buf.as_ptr() as *const _, buf.len());
            ffi::gpgme_data_write(self.as_raw(), buf, len)
        };
        if result >= 0 {
            Ok(result as usize)
        } else {
            Err(Error::last_os_error().into())
        }
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> Seek for Data<'a> {
    #[inline]
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let (off, whence) = match pos {
            io::SeekFrom::Start(off) => (off.value_into().unwrap_or_saturate(), libc::SEEK_SET),
            io::SeekFrom::End(off) => (off.value_into().unwrap_or_saturate(), libc::SEEK_END),
            io::SeekFrom::Current(off) => (off.value_into().unwrap_or_saturate(), libc::SEEK_CUR),
        };
        let result = unsafe { ffi::gpgme_data_seek(self.as_raw(), off, whence) };
        if result >= 0 {
            Ok(result as u64)
        } else {
            Err(Error::last_os_error().into())
        }
    }
}

extern "C" fn read_callback<S: Read>(handle: *mut libc::c_void, buffer: *mut libc::c_void, size: libc::size_t)
    -> libc::ssize_t {
    let handle = handle as *mut CallbackWrapper<S>;
    unsafe {
        let slice = slice::from_raw_parts_mut(buffer as *mut u8, size);
        (*handle)
            .inner
            .read(slice)
            .map(|n| n as libc::ssize_t)
            .unwrap_or_else(|err| {
                ffi::gpgme_err_set_errno(Error::from(err).to_errno());
                -1
            })
    }
}

extern "C" fn write_callback<S: Write>(handle: *mut libc::c_void, buffer: *const libc::c_void, size: libc::size_t)
    -> libc::ssize_t {
    let handle = handle as *mut CallbackWrapper<S>;
    unsafe {
        let slice = slice::from_raw_parts(buffer as *const _, size);
        (*handle)
            .inner
            .write(slice)
            .map(|n| n as libc::ssize_t)
            .unwrap_or_else(|err| {
                ffi::gpgme_err_set_errno(Error::from(err).to_errno());
                -1
            })
    }
}

extern "C" fn seek_callback<S: Seek>(handle: *mut libc::c_void, offset: libc::off_t, whence: libc::c_int)
    -> libc::off_t {
    let handle = handle as *mut CallbackWrapper<S>;
    let pos = match whence {
        libc::SEEK_SET => io::SeekFrom::Start(offset.value_into().unwrap_or_saturate()),
        libc::SEEK_END => io::SeekFrom::End(offset.value_into().unwrap_or_saturate()),
        libc::SEEK_CUR => io::SeekFrom::Current(offset.value_into().unwrap_or_saturate()),
        _ => unsafe {
            ffi::gpgme_err_set_errno(ffi::gpgme_err_code_to_errno(error::GPG_ERR_EINVAL));
            return -1;
        },
    };
    unsafe {
        (*handle)
            .inner
            .seek(pos)
            .map(|n| n.value_into().unwrap_or_saturate())
            .unwrap_or_else(|err| {
                ffi::gpgme_err_set_errno(Error::from(err).to_errno());
                -1
            })
    }
}

extern "C" fn release_callback<S>(handle: *mut libc::c_void) {
    unsafe {
        drop(Box::from_raw(handle as *mut CallbackWrapper<S>));
    }
}

pub trait DataSource<'a> {
    type Output: BorrowMut<Data<'a>>;

    fn into_data(self) -> Result<Self::Output>;
}

pub trait DataSink<'a> {
    type Output: BorrowMut<Data<'a>>;

    fn into_data(self) -> Result<Self::Output>;
}

pub trait IntoData<'a> {
    type Output: BorrowMut<Data<'a>>;

    fn into_data(self) -> Result<Self::Output>;
}

impl<'a, 'b> IntoData<'a> for &'b mut Data<'a> {
    type Output = Self;

    fn into_data(self) -> Result<Self> {
        Ok(self)
    }
}

impl<'a> IntoData<'a> for Data<'a> {
    type Output = Self;

    fn into_data(self) -> Result<Self> {
        Ok(self)
    }
}

impl<'a> IntoData<'a> for &'a [u8] {
    type Output = Data<'a>;

    fn into_data(self) -> Result<Data<'a>> {
        Data::from_buffer(self)
    }
}

impl<'a> IntoData<'a> for &'a Vec<u8> {
    type Output = Data<'a>;

    fn into_data(self) -> Result<Data<'a>> {
        Data::from_buffer(self)
    }
}

impl<'a> IntoData<'a> for &'a mut Vec<u8> {
    type Output = Data<'a>;

    fn into_data(self) -> Result<Data<'a>> {
        Data::from_writer(self).map_err(|e| e.error())
    }
}

impl IntoData<'static> for Vec<u8> {
    type Output = Data<'static>;

    fn into_data(self) -> Result<Data<'static>> {
        Data::from_bytes(self)
    }
}

impl<'a> IntoData<'a> for &'a str {
    type Output = Data<'a>;

    fn into_data(self) -> Result<Data<'a>> {
        Data::from_buffer(self)
    }
}

impl IntoData<'static> for String {
    type Output = Data<'static>;

    fn into_data(self) -> Result<Data<'static>> {
        Data::from_bytes(self)
    }
}

impl<'a> IntoData<'a> for &'a File {
    type Output = Data<'a>;

    fn into_data(self) -> Result<Data<'a>> {
        Data::from_seekable_stream(self).map_err(|e| e.error())
    }
}

impl<'a> IntoData<'a> for &'a mut File {
    type Output = Data<'a>;

    fn into_data(self) -> Result<Data<'a>> {
        Data::from_seekable_stream(self).map_err(|e| e.error())
    }
}

impl IntoData<'static> for File {
    type Output = Data<'static>;

    fn into_data(self) -> Result<Data<'static>> {
        Data::from_seekable_stream(self).map_err(|e| e.error())
    }
}
