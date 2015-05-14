use std::convert::AsRef;
use std::ffi::{CStr, CString};
use std::io;
use std::io::prelude::*;
use std::marker::PhantomData;
use std::mem;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr;
use std::result::Result as StdResult;
use std::slice;
use std::str;
use std::string;

use libc;

use enum_primitive::FromPrimitive;

use gpgme_sys as sys;

use error::{Error, Result};

enum_from_primitive! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub enum DataEncoding {
        None,
        Binary,
        Base64,
        Armor,
        Url,
        UrlEsc,
        Url0,
    }
}

enum_from_primitive! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub enum DataType {
        Invalid = 0,
        Unknown = 1,
        PgpSigned = 0x10,
        PgpOther = 0x12,
        PgpKey = 0x13,
        CmsSigned = 0x20,
        CmsEncrypted = 0x21,
        CmsOther = 0x22,
        X509Cert = 0x23,
        Pkcs12 = 0x24,
    }
}

struct CallbackWrapper<S> {
    cbs: sys::gpgme_data_cbs,
    inner: S,
}

extern fn read_callback<S: Read>(handle: *mut libc::c_void,
                                 buffer: *mut libc::c_void,
                                 size: libc::size_t) -> libc::ssize_t {
    let handle = handle as *mut CallbackWrapper<S>;
    let result = unsafe {
        let slice = slice::from_raw_parts_mut(buffer as *mut u8, size as usize);
        (*handle).inner.read(slice)
    };
    if !result.is_err() {
        result.unwrap() as libc::ssize_t
    } else {
        unsafe {
            let err = result.err().and_then(|err| err.raw_os_error()).unwrap_or_else(|| {
                sys::gpgme_err_code_to_errno(sys::GPG_ERR_EIO)
            });
            sys::gpgme_err_set_errno(err);
            -1 as libc::ssize_t
        }
    }
}

extern fn write_callback<S: Write>(handle: *mut libc::c_void,
                                   buffer: *const libc::c_void,
                                   size: libc::size_t) -> libc::ssize_t {
    let handle = handle as *mut CallbackWrapper<S>;
    let result = unsafe {
        let slice = slice::from_raw_parts(buffer as *const u8, size as usize);
        (*handle).inner.write(slice)
    };
    if !result.is_err() {
        result.unwrap() as libc::ssize_t
    } else {
        unsafe {
            let err = result.err().and_then(|err| err.raw_os_error()).unwrap_or_else(|| {
                sys::gpgme_err_code_to_errno(sys::GPG_ERR_EIO)
            });
            sys::gpgme_err_set_errno(err);
            -1 as libc::ssize_t
        }
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
            return -1;
        },
    };
    let result = unsafe {
        (*handle).inner.seek(pos)
    };
    if !result.is_err() {
        result.unwrap() as libc::off_t
    } else {
        unsafe {
            let err = result.err().and_then(|err| err.raw_os_error()).unwrap_or_else(|| {
                sys::gpgme_err_code_to_errno(sys::GPG_ERR_EIO)
            });
            sys::gpgme_err_set_errno(err);
            -1 as libc::ssize_t
        }
    }
}

extern fn release_callback<S>(handle: *mut libc::c_void) {
    let handle: Box<CallbackWrapper<S>> = unsafe {
        mem::transmute(handle)
    };
    drop(handle);
}

#[derive(Debug)]
pub struct Data<'a> {
    raw: sys::gpgme_data_t,
    phantom: PhantomData<&'a sys::gpgme_data_t>,
}

impl<'a> Data<'a> {
    pub fn new() -> Result<Data<'static>> {
        let mut data: sys::gpgme_data_t = ptr::null_mut();
        let result = unsafe {
            sys::gpgme_data_new(&mut data)
        };
        if result == 0 {
            Ok(Data { raw: data, phantom: PhantomData })
        } else {
            Err(Error::new(result))
        }
    }

    pub unsafe fn from_raw(data: sys::gpgme_data_t) -> Data<'static> {
        Data { raw: data, phantom: PhantomData }
    }

    pub unsafe fn raw(&self) -> sys::gpgme_data_t {
        self.raw
    }

    pub fn load<P: AsRef<Path>>(path: &P) -> Result<Data<'static>> {
        let mut data: sys::gpgme_data_t = ptr::null_mut();
        let filename = path.as_ref().to_str().and_then(|s| CString::new(s.as_bytes()).ok());
        if filename.is_none() {
            return Err(Error::from_source(sys::GPG_ERR_SOURCE_GPGME, sys::GPG_ERR_INV_VALUE));
        }
        let result = unsafe {
            sys::gpgme_data_new_from_file(&mut data, filename.unwrap().as_ptr(), 1)
        };
        if result == 0 {
            Ok(Data { raw: data, phantom: PhantomData })
        } else {
            Err(Error::new(result))
        }
    }

    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Data<'static>> {
        let mut data: sys::gpgme_data_t = ptr::null_mut();
        let bytes = bytes.as_ref();
        let result = unsafe {
            sys::gpgme_data_new_from_mem(&mut data, bytes.as_ptr() as *const _,
                                         bytes.len() as u64, 1)
        };
        if result == 0 {
            Ok(Data { raw: data, phantom: PhantomData })
        } else {
            Err(Error::new(result))
        }
    }

    pub fn from_fd<'b, T: AsRawFd>(file: &'b T) -> Result<Data<'b>> {
        let mut data: sys::gpgme_data_t = ptr::null_mut();
        let result = unsafe {
            sys::gpgme_data_new_from_fd(&mut data, file.as_raw_fd())
        };
        if result == 0 {
            Ok(Data { raw: data, phantom: PhantomData })
        } else {
            Err(Error::new(result))
        }
    }

    pub unsafe fn from_file(file: *mut libc::FILE) -> Result<Data<'static>> {
        let mut data: sys::gpgme_data_t = ptr::null_mut();
        let result = sys::gpgme_data_new_from_stream(&mut data, file);
        if result == 0 {
            Ok(Data { raw: data, phantom: PhantomData })
        } else {
            Err(Error::new(result))
        }
    }

    unsafe fn from_callbacks<S>(cbs: sys::gpgme_data_cbs, src: S) -> StdResult<Data<'static>, S> {
        let mut data: sys::gpgme_data_t = ptr::null_mut();
        let mut src = Box::new(CallbackWrapper::<S> {
            cbs: cbs,
            inner: src,
        });
        let cbs: sys::gpgme_data_cbs_t = &mut src.cbs;
        let ptr: *mut libc::c_void = mem::transmute(src);
        let result = sys::gpgme_data_new_from_cbs(&mut data, cbs, ptr);
        if result == 0 {
            Ok(Data { raw: data, phantom: PhantomData })
        } else {
            let src: Box<S> = mem::transmute(ptr);
            Err(*src)
        }
    }

    pub fn from_reader<R: Read>(r: R) -> StdResult<Data<'static>, R> {
        let cbs = sys::gpgme_data_cbs {
            read: Some(read_callback::<R>),
            write: None,
            seek: None,
            release: Some(release_callback::<R>),
        };
        unsafe { Data::from_callbacks(cbs, r) }
    }

    pub fn from_seekable_reader<R: Read + Seek>(r: R) -> StdResult<Data<'static>, R> {
        let cbs = sys::gpgme_data_cbs {
            read: Some(read_callback::<R>),
            write: None,
            seek: Some(seek_callback::<R>),
            release: Some(release_callback::<R>),
        };
        unsafe { Data::from_callbacks(cbs, r) }
    }

    pub fn from_writer<W: Write>(w: W) -> StdResult<Data<'static>, W> {
        let cbs = sys::gpgme_data_cbs {
            read: None,
            write: Some(write_callback::<W>),
            seek: None,
            release: Some(release_callback::<W>),
        };
        unsafe { Data::from_callbacks(cbs, w) }
    }

    pub fn from_seekable_writer<W: Write + Seek>(w: W) -> StdResult<Data<'static>, W> {
        let cbs = sys::gpgme_data_cbs {
            read: None,
            write: Some(write_callback::<W>),
            seek: Some(seek_callback::<W>),
            release: Some(release_callback::<W>),
        };
        unsafe { Data::from_callbacks(cbs, w) }
    }

    pub fn from_stream<S: Read + Write>(s: S) -> StdResult<Data<'static>, S> {
        let cbs = sys::gpgme_data_cbs {
            read: Some(read_callback::<S>),
            write: Some(write_callback::<S>),
            seek: None,
            release: Some(release_callback::<S>),
        };
        unsafe { Data::from_callbacks(cbs, s) }
    }

    pub fn from_seekable_stream<S: Read + Write + Seek>(s: S) -> StdResult<Data<'static>, S> {
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
            let result = sys::gpgme_data_get_file_name(self.raw);
            if !result.is_null() {
                str::from_utf8(CStr::from_ptr(result as *const _).to_bytes()).ok()
            } else {
                None
            }
        }
    }

    pub fn set_file_name(&mut self, name: Option<&str>) -> Result<()> {
        let name = name.map(CString::new);
        if name.is_some() && name.as_ref().unwrap().is_err() {
            return Err(Error::from_source(sys::GPG_ERR_SOURCE_USER_1, sys::GPG_ERR_INV_VALUE));
        }
        let result = unsafe {
            sys::gpgme_data_set_file_name(self.raw, name.map_or(ptr::null(), |s| s.unwrap().as_ptr()))
        };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::new(result))
        }
    }

    pub fn encoding(&self) -> DataEncoding {
        unsafe {
            DataEncoding::from_u32(sys::gpgme_data_get_encoding(self.raw) as u32).unwrap()
        }
    }

    pub fn set_encoding(&mut self, enc: DataEncoding) -> Result<()> {
        let result = unsafe {
            sys::gpgme_data_set_encoding(
                self.raw, sys::gpgme_data_encoding_t::from_u32(enc as u32).unwrap())
        };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::new(result))
        }
    }

    pub fn identify(&mut self) -> DataType {
        unsafe {
            DataType::from_u32(sys::gpgme_data_identify(self.raw, 0) as u32).unwrap()
        }
    }

    pub fn into_bytes(self) -> Option<Vec<u8>> {
        unsafe {
            let mut size = 0;
            let buf = sys::gpgme_data_release_and_get_mem(self.raw, &mut size);
            mem::forget(self);

            if !buf.is_null() {
                let mut dst = Vec::with_capacity(size as usize);
                dst.set_len(size as usize);
                ptr::copy_nonoverlapping(buf as *const _, dst.as_mut_ptr(), size as usize);
                sys::gpgme_free(buf as *mut _);
                Some(dst)
            } else {
                None
            }
        }
    }

    pub fn into_string(self) -> Option<StdResult<String, string::FromUtf8Error>> {
        self.into_bytes().map(String::from_utf8)
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
            Err(io::Error::last_os_error())
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
            Err(io::Error::last_os_error())
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
            Err(io::Error::last_os_error())
        }
    }
}
