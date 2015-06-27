use std::ffi::CString;
use std::fmt;
use std::io;
use std::io::prelude::*;
use std::marker::PhantomData;
use std::mem;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr;
use std::result;
use std::slice;
use std::string::FromUtf8Error;

use libc;

use enum_primitive::FromPrimitive;

use gpgme_sys as sys;

use error::{Error, Result};
use utils;

enum_from_primitive! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub enum DataEncoding {
        Unknown = -1,
        None = sys::GPGME_DATA_ENCODING_NONE as isize,
        Binary = sys::GPGME_DATA_ENCODING_BINARY as isize,
        Base64 = sys::GPGME_DATA_ENCODING_BASE64 as isize,
        Armor = sys::GPGME_DATA_ENCODING_ARMOR as isize,
        Url = sys::GPGME_DATA_ENCODING_URL as isize,
        UrlEsc = sys::GPGME_DATA_ENCODING_URLESC as isize,
        Url0 = sys::GPGME_DATA_ENCODING_URL0 as isize,
    }
}

enum_from_primitive! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub enum DataType {
        Unknown = sys::GPGME_DATA_TYPE_UNKNOWN as isize,
        Invalid = sys::GPGME_DATA_TYPE_INVALID as isize,
        PgpSigned = sys::GPGME_DATA_TYPE_PGP_SIGNED as isize,
        PgpOther = sys::GPGME_DATA_TYPE_PGP_OTHER as isize,
        PgpKey = sys::GPGME_DATA_TYPE_PGP_KEY as isize,
        CmsSigned = sys::GPGME_DATA_TYPE_CMS_SIGNED as isize,
        CmsEncrypted = sys::GPGME_DATA_TYPE_CMS_ENCRYPTED as isize,
        CmsOther = sys::GPGME_DATA_TYPE_CMS_OTHER as isize,
        X509Cert = sys::GPGME_DATA_TYPE_X509_CERT as isize,
        Pkcs12 = sys::GPGME_DATA_TYPE_PKCS12 as isize,
    }
}

struct CallbackWrapper<S> {
    cbs: sys::gpgme_data_cbs,
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
pub struct Data<'a> {
    raw: sys::gpgme_data_t,
    phantom: PhantomData<&'a sys::gpgme_data_t>,
}

impl<'a> Data<'a> {
    pub unsafe fn from_raw(data: sys::gpgme_data_t) -> Data<'static> {
        Data { raw: data, phantom: PhantomData }
    }

    pub fn as_raw(&self) -> sys::gpgme_data_t {
        self.raw
    }

    pub fn stdin() -> Result<Data<'static>> {
        Data::from_reader(io::stdin()).map_err(|err| err.error())
    }

    pub fn stdout() -> Result<Data<'static>> {
        Data::from_writer(io::stdout()).map_err(|err| err.error())
    }

    pub fn stderr() -> Result<Data<'static>> {
        Data::from_writer(io::stdout()).map_err(|err| err.error())
    }

    /// Constructs an empty data object.
    pub fn new() -> Result<Data<'static>> {
        let mut data: sys::gpgme_data_t = ptr::null_mut();
        unsafe {
            return_err!(sys::gpgme_data_new(&mut data));
        }
        Ok(Data { raw: data, phantom: PhantomData })
    }

    /// Constructs a data object and fills it with the contents of the file
    /// referenced by `path`.
    pub fn load<P: AsRef<Path>>(path: &P) -> Result<Data<'static>> {
        let mut data: sys::gpgme_data_t = ptr::null_mut();
        let filename = try!(path.as_ref().to_str().and_then(|s| CString::new(s.as_bytes()).ok())
            .ok_or(Error::from_source(sys::GPG_ERR_SOURCE_USER_1, sys::GPG_ERR_INV_VALUE)));
        unsafe {
            return_err!(sys::gpgme_data_new_from_file(&mut data, filename.as_ptr(), 1));
        }
        Ok(Data { raw: data, phantom: PhantomData })
    }

    /// Constructs a data object and fills it with a copy of `bytes`.
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Data<'static>> {
        let mut data: sys::gpgme_data_t = ptr::null_mut();
        let bytes = bytes.as_ref();
        unsafe {
            return_err!(sys::gpgme_data_new_from_mem(&mut data, bytes.as_ptr() as *const _,
                                                     bytes.len() as u64, 1));
        }
        Ok(Data { raw: data, phantom: PhantomData })
    }

    /// Constructs a data object which copies from `buf` as needed.
    pub fn from_buffer<B: AsRef<[u8]> + ?Sized>(buf: &B) -> Result<Data> {
        let mut data: sys::gpgme_data_t = ptr::null_mut();
        let buf = buf.as_ref();
        unsafe {
            return_err!(sys::gpgme_data_new_from_mem(&mut data, buf.as_ptr() as *const _,
                                                     buf.len() as u64, 0));
        }
        Ok(Data { raw: data, phantom: PhantomData })
    }

    #[cfg(unix)]
    pub fn from_fd<T: AsRawFd + ?Sized>(file: &T) -> Result<Data> {
        let mut data: sys::gpgme_data_t = ptr::null_mut();
        unsafe {
            return_err!(sys::gpgme_data_new_from_fd(&mut data, file.as_raw_fd()));
        }
        Ok(Data { raw: data, phantom: PhantomData })
    }

    pub unsafe fn from_raw_file<'b>(file: *mut libc::FILE) -> Result<Data<'b>> {
        let mut data: sys::gpgme_data_t = ptr::null_mut();
        return_err!(sys::gpgme_data_new_from_stream(&mut data, file));
        Ok(Data { raw: data, phantom: PhantomData })
    }

    unsafe fn from_callbacks<S: Send + 'static>(cbs: sys::gpgme_data_cbs, src: S)
            -> result::Result<Data<'static>, WrappedError<S>> {
        let mut data: sys::gpgme_data_t = ptr::null_mut();
        let mut src = Box::new(CallbackWrapper {
            cbs: cbs,
            inner: src,
        });
        let cbs: sys::gpgme_data_cbs_t = &mut src.cbs;
        let ptr: *mut libc::c_void = mem::transmute(src);
        let result = sys::gpgme_data_new_from_cbs(&mut data, cbs, ptr);
        if result == 0 {
            Ok(Data { raw: data, phantom: PhantomData })
        } else {
            let error = Error::new(result);
            let inner = mem::transmute::<_, Box<CallbackWrapper<S>>>(ptr).inner;
            Err(WrappedError(error, inner))
        }
    }

    pub fn from_reader<R: Send + 'static>(r: R) -> result::Result<Data<'static>, WrappedError<R>>
            where R: Read {
        let cbs = sys::gpgme_data_cbs {
            read: Some(read_callback::<R>),
            write: None,
            seek: None,
            release: Some(release_callback::<R>),
        };
        unsafe { Data::from_callbacks(cbs, r) }
    }

    pub fn from_seekable_reader<R: Send + 'static>(r: R)
            -> result::Result<Data<'static>, WrappedError<R>> where R: Read + Seek {
        let cbs = sys::gpgme_data_cbs {
            read: Some(read_callback::<R>),
            write: None,
            seek: Some(seek_callback::<R>),
            release: Some(release_callback::<R>),
        };
        unsafe { Data::from_callbacks(cbs, r) }
    }

    pub fn from_writer<W: Send + 'static>(w: W) -> result::Result<Data<'static>, WrappedError<W>>
            where W: Write {
        let cbs = sys::gpgme_data_cbs {
            read: None,
            write: Some(write_callback::<W>),
            seek: None,
            release: Some(release_callback::<W>),
        };
        unsafe { Data::from_callbacks(cbs, w) }
    }

    pub fn from_seekable_writer<W: Send + 'static>(w: W)
            -> result::Result<Data<'static>, WrappedError<W>> where W: Write + Seek {
        let cbs = sys::gpgme_data_cbs {
            read: None,
            write: Some(write_callback::<W>),
            seek: Some(seek_callback::<W>),
            release: Some(release_callback::<W>),
        };
        unsafe { Data::from_callbacks(cbs, w) }
    }

    pub fn from_stream<S: Send + 'static>(s: S) -> result::Result<Data<'static>, WrappedError<S>>
            where S: Read + Write {
        let cbs = sys::gpgme_data_cbs {
            read: Some(read_callback::<S>),
            write: Some(write_callback::<S>),
            seek: None,
            release: Some(release_callback::<S>),
        };
        unsafe { Data::from_callbacks(cbs, s) }
    }

    pub fn from_seekable_stream<S: Send + 'static>(s: S)
            -> result::Result<Data<'static>, WrappedError<S>> where S: Read + Write + Seek {
        let cbs = sys::gpgme_data_cbs {
            read: Some(read_callback::<S>),
            write: Some(write_callback::<S>),
            seek: Some(seek_callback::<S>),
            release: Some(release_callback::<S>),
        };
        unsafe { Data::from_callbacks(cbs, s) }
    }

    pub fn file_name(&self) -> Option<&str> {
        unsafe {
            utils::from_cstr(sys::gpgme_data_get_file_name(self.raw))
        }
    }

    pub fn clear_file_name(&mut self) -> Result<()> {
        unsafe {
            return_err!(sys::gpgme_data_set_file_name(self.raw, ptr::null()));
        }
        Ok(())
    }

    pub fn set_file_name<S: Into<String>>(&mut self, name: S) -> Result<()> {
        let name = try!(CString::new(name.into()));
        unsafe {
            return_err!(sys::gpgme_data_set_file_name(self.raw, name.as_ptr()));
        }
        Ok(())
    }

    pub fn encoding(&self) -> DataEncoding {
        unsafe {
            DataEncoding::from_u64(sys::gpgme_data_get_encoding(self.raw) as u64)
                .unwrap_or(DataEncoding::Unknown)
        }
    }

    pub fn set_encoding(&mut self, enc: DataEncoding) -> Result<()> {
        unsafe {
            return_err!(sys::gpgme_data_set_encoding(self.raw, enc as sys::gpgme_data_encoding_t))
        }
        Ok(())
    }

    // GPGME_VERSION >= 1.4.3
    pub fn identify(&mut self) -> DataType {
        unsafe {
            DataType::from_u64(sys::gpgme_data_identify(self.raw, 0) as u64)
                .unwrap_or(DataType::Unknown)
        }
    }

    pub fn into_bytes(self) -> Option<Vec<u8>> {
        unsafe {
            let mut size = 0;
            let buf = sys::gpgme_data_release_and_get_mem(self.raw, &mut size);
            mem::forget(self);

            if !buf.is_null() {
                let mut dst = Vec::with_capacity(size as usize);
                ptr::copy_nonoverlapping(buf as *const _, dst.as_mut_ptr(), size as usize);
                sys::gpgme_free(buf as *mut _);
                dst.set_len(size as usize);
                Some(dst)
            } else {
                None
            }
        }
    }

    pub fn into_string(self) -> result::Result<Option<String>, FromUtf8Error> {
        self.into_bytes().map_or(Ok(None), |x| String::from_utf8(x).map(Some))
    }
}

impl<'a> Drop for Data<'a> {
    fn drop(&mut self) {
        unsafe {
            sys::gpgme_data_release(self.raw);
        }
    }
}

impl<'a> Read for Data<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = buf.len();
        let result = unsafe {
            sys::gpgme_data_read(self.raw, buf.as_mut_ptr() as *mut _,
                                len as libc::size_t)
        };
        if result >= 0 {
            Ok(result as usize)
        } else {
            Err(Error::last_os_error().into())
        }
    }
}

impl<'a> Write for Data<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let result = unsafe {
            sys::gpgme_data_write(self.raw, buf.as_ptr() as *const _,
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

impl<'a> Seek for Data<'a> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let (off, whence) = match pos {
            io::SeekFrom::Start(off) => (off as libc::off_t, libc::SEEK_SET),
            io::SeekFrom::End(off) => (off as libc::off_t, libc::SEEK_END),
            io::SeekFrom::Current(off) => (off as libc::off_t, libc::SEEK_CUR),
        };
        let result = unsafe {
            sys::gpgme_data_seek(self.raw, off, whence)
        };
        if result >= 0 {
            Ok(result as u64)
        } else {
            Err(Error::last_os_error().into())
        }
    }
}

extern fn read_callback<S: Read>(handle: *mut libc::c_void,
                                 buffer: *mut libc::c_void,
                                 size: libc::size_t) -> libc::ssize_t {
    let handle = handle as *mut CallbackWrapper<S>;
    unsafe {
        let slice = slice::from_raw_parts_mut(buffer as *mut u8, size as usize);
        (*handle).inner.read(slice).map(|n| n as libc::ssize_t).unwrap_or_else(|err| {
            sys::gpgme_err_set_errno(Error::from(err).to_errno());
            -1
        })
    }
}

extern fn write_callback<S: Write>(handle: *mut libc::c_void,
                                   buffer: *const libc::c_void,
                                   size: libc::size_t) -> libc::ssize_t {
    let handle = handle as *mut CallbackWrapper<S>;
    unsafe {
        let slice = slice::from_raw_parts(buffer as *const u8, size as usize);
        (*handle).inner.write(slice).map(|n| n as libc::ssize_t).unwrap_or_else(|err| {
            sys::gpgme_err_set_errno(Error::from(err).to_errno());
            -1
        })
    }
}

extern fn seek_callback<S: Seek>(handle: *mut libc::c_void,
                                 offset: libc::off_t,
                                 whence: libc::c_int) -> libc::off_t {
    let handle = handle as *mut CallbackWrapper<S>;
    let pos = match whence {
        libc::SEEK_SET => io::SeekFrom::Start(offset as u64),
        libc::SEEK_END => io::SeekFrom::End(offset as i64),
        libc::SEEK_CUR => io::SeekFrom::Current(offset as i64),
        _ => {
            unsafe {
                sys::gpgme_err_set_errno(sys::gpgme_err_code_to_errno(sys::GPG_ERR_EINVAL));
            }
            return -1 as libc::off_t;
        },
    };
    unsafe {
        (*handle).inner.seek(pos).map(|n| n as libc::off_t).unwrap_or_else(|err| {
            sys::gpgme_err_set_errno(Error::from(err).to_errno());
            -1
        })
    }
}

extern fn release_callback<S>(handle: *mut libc::c_void) {
    unsafe {
        drop(mem::transmute::<_, Box<CallbackWrapper<S>>>(handle));
    }
}
