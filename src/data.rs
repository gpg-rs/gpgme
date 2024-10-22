use std::{
    borrow::BorrowMut,
    error::Error as StdError,
    ffi::CStr,
    fmt,
    fs::File,
    io::{self, prelude::*, Cursor},
    marker::PhantomData,
    ptr, slice,
    str::Utf8Error,
};

#[cfg(unix)]
use std::os::fd::{AsRawFd, BorrowedFd};

use conv::{UnwrapOrSaturate, ValueInto};
use ffi::{self, gpgme_off_t};
use libc;
use static_assertions::{assert_impl_all, assert_not_impl_any};

use crate::{
    utils::{self, convert_err, CStrArgument},
    Error, NonNull, Result,
};

assert_impl_all!(Data<'_>: Send);
assert_not_impl_any!(Data<'_>: Sync);

ffi_enum_wrapper! {
    /// Upstream documentation:
    /// [`gpgme_data_encoding_t`](https://www.gnupg.org/documentation/manuals/gpgme/Data-Buffer-Meta_002dData.html#index-enum-gpgme_005fdata_005fencoding_005ft)
    #[non_exhaustive]
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
    /// Upstream documentation:
    /// [`gpgme_data_type_t`](https://www.gnupg.org/documentation/manuals/gpgme/Data-Buffer-Convenience.html#index-enum-gpgme_005fdata_005ftype_005ft)
    #[non_exhaustive]
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
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S> fmt::Display for WrappedError<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, fmt)
    }
}

impl<S> StdError for WrappedError<S> {
    fn description(&self) -> &str {
        #[allow(deprecated)]
        StdError::description(&self.0)
    }

    fn cause(&self) -> Option<&dyn StdError> {
        Some(&self.0)
    }

    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.0)
    }
}

/// Upstream documentation:
/// [`gpgme_data_t`](https://www.gnupg.org/documentation/manuals/gpgme/Exchanging-Data.html#Exchanging-Data)
#[must_use]
#[derive(Debug)]
pub struct Data<'data>(NonNull<ffi::gpgme_data_t>, PhantomData<&'data mut ()>);

unsafe impl Send for Data<'_> {}

impl Drop for Data<'_> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::gpgme_data_release(self.as_raw());
        }
    }
}

impl<'data> Data<'data> {
    impl_wrapper!(ffi::gpgme_data_t, PhantomData);

    #[inline]
    pub fn stdin() -> Result<Self> {
        Self::try_from(io::stdin())
    }

    #[inline]
    pub fn stdout() -> Result<Self> {
        Self::try_from(io::stdout())
    }

    #[inline]
    pub fn stderr() -> Result<Self> {
        Self::try_from(io::stderr())
    }

    /// Constructs an empty data object.
    ///
    /// Upstream documentation:
    /// [`gpgme_data_new`](https://www.gnupg.org/documentation/manuals/gpgme/Memory-Based-Data-Buffers.html#index-gpgme_005fdata_005fnew)
    #[inline]
    pub fn new() -> Result<Self> {
        crate::init();
        unsafe {
            let mut data = ptr::null_mut();
            convert_err(ffi::gpgme_data_new(&mut data))?;
            Ok(Data::from_raw(data))
        }
    }

    /// Constructs a data object and fills it with the contents of the file
    /// referenced by `path`.
    ///
    /// Upstream documentation:
    /// [`gpgme_data_new_from_file`](https://www.gnupg.org/documentation/manuals/gpgme/Memory-Based-Data-Buffers.html#index-gpgme_005fdata_005fnew_005ffrom_005ffile)
    #[inline]
    pub fn load(path: impl CStrArgument) -> Result<Self> {
        crate::init();
        let path = path.into_cstr();
        unsafe {
            let mut data = ptr::null_mut();
            convert_err(ffi::gpgme_data_new_from_file(
                &mut data,
                path.as_ref().as_ptr(),
                1,
            ))?;
            Ok(Data::from_raw(data))
        }
    }

    /// Constructs a data object and fills it with a copy of `bytes`.
    ///
    /// Upstream documentation:
    /// [`gpgme_data_new_from_mem`](https://www.gnupg.org/documentation/manuals/gpgme/Memory-Based-Data-Buffers.html#index-gpgme_005fdata_005fnew_005ffrom_005fmem)
    #[inline]
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        crate::init();
        let bytes = bytes.as_ref();
        unsafe {
            let mut data = ptr::null_mut();
            convert_err(ffi::gpgme_data_new_from_mem(
                &mut data,
                bytes.as_ptr().cast(),
                bytes.len(),
                1,
            ))?;
            Ok(Data::from_raw(data))
        }
    }

    /// Constructs a data object which copies from `buf` as needed.
    ///
    /// Upstream documentation:
    /// [`gpgme_data_new_from_mem`](https://www.gnupg.org/documentation/manuals/gpgme/Memory-Based-Data-Buffers.html#index-gpgme_005fdata_005fnew_005ffrom_005fmem)
    #[inline]
    pub fn from_buffer(buf: &'data (impl AsRef<[u8]> + ?Sized)) -> Result<Self> {
        crate::init();
        let buf = buf.as_ref();
        unsafe {
            let mut data = ptr::null_mut();
            convert_err(ffi::gpgme_data_new_from_mem(
                &mut data,
                buf.as_ptr().cast(),
                buf.len(),
                0,
            ))?;
            Ok(Data::from_raw(data))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_data_new_from_fd`](https://www.gnupg.org/documentation/manuals/gpgme/File-Based-Data-Buffers.html#index-gpgme_005fdata_005fnew_005ffrom_005ffd)
    #[inline]
    #[cfg(unix)]
    pub fn from_borrowed_fd(fd: BorrowedFd<'data>) -> Result<Self> {
        crate::init();
        unsafe {
            let mut data = ptr::null_mut();
            convert_err(ffi::gpgme_data_new_from_fd(&mut data, fd.as_raw_fd()))?;
            Ok(Data::from_raw(data))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_data_new_from_fd`](https://www.gnupg.org/documentation/manuals/gpgme/File-Based-Data-Buffers.html#index-gpgme_005fdata_005fnew_005ffrom_005ffd)
    #[inline]
    #[cfg(unix)]
    #[deprecated(note = "Use Data::from_borrowed_fd", since = "0.11.1")]
    pub fn from_fd(file: &'data (impl AsRawFd + ?Sized)) -> Result<Self> {
        crate::init();
        unsafe {
            let mut data = ptr::null_mut();
            convert_err(ffi::gpgme_data_new_from_fd(&mut data, file.as_raw_fd()))?;
            Ok(Data::from_raw(data))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_data_new_from_stream`](https://www.gnupg.org/documentation/manuals/gpgme/File-Based-Data-Buffers.html#index-gpgme_005fdata_005fnew_005ffrom_005fstream)
    ///
    /// # Safety
    ///
    /// The provided `FILE` object must be valid.
    #[inline]
    pub unsafe fn from_raw_file(file: *mut libc::FILE) -> Result<Self> {
        crate::init();
        let mut data = ptr::null_mut();
        convert_err(ffi::gpgme_data_new_from_stream(&mut data, file))?;
        Ok(Data::from_raw(data))
    }

    unsafe fn from_callbacks<S>(cbs: ffi::gpgme_data_cbs, src: S) -> Result<Self, WrappedError<S>>
    where
        S: Send + 'data,
    {
        crate::init();
        let src = Box::into_raw(Box::new(CallbackWrapper { inner: src, cbs }));
        let cbs = ptr::addr_of_mut!((*src).cbs);
        let mut data = ptr::null_mut();
        match convert_err(ffi::gpgme_data_new_from_cbs(&mut data, cbs, src.cast())) {
            Ok(()) => Ok(Data::from_raw(data)),
            Err(e) => Err(WrappedError(e, Box::from_raw(src).inner)),
        }
    }

    /// Returns a new [`DataBuilder`] wrapping the provided value.
    #[inline]
    pub fn builder<T: Send>(inner: T) -> DataBuilder<T> {
        DataBuilder::new(inner)
    }

    #[inline]
    #[deprecated(note = "Use Data::builder instead.", since = "0.11.1")]
    pub fn from_reader<R>(r: R) -> Result<Self, WrappedError<R>>
    where
        R: Read + Send + 'data,
    {
        Self::builder(r).readable().try_build()
    }

    #[inline]
    #[deprecated(note = "Use Data::builder instead.", since = "0.11.1")]
    pub fn from_seekable_reader<R>(r: R) -> Result<Self, WrappedError<R>>
    where
        R: Read + Seek + Send + 'data,
    {
        Self::builder(r).readable().seekable().try_build()
    }

    #[inline]
    #[deprecated(note = "Use Data::builder instead.", since = "0.11.1")]
    pub fn from_writer<W>(w: W) -> Result<Self, WrappedError<W>>
    where
        W: Write + Send + 'data,
    {
        Self::builder(w).writable().try_build()
    }

    #[inline]
    #[deprecated(note = "Use Data::builder instead.", since = "0.11.1")]
    pub fn from_seekable_writer<W>(w: W) -> Result<Self, WrappedError<W>>
    where
        W: Write + Seek + Send + 'data,
    {
        Self::builder(w).writable().seekable().try_build()
    }

    #[inline]
    #[deprecated(note = "Use Data::builder instead.", since = "0.11.1")]
    pub fn from_stream<S>(s: S) -> Result<Self, WrappedError<S>>
    where
        S: Read + Write + Send + 'data,
    {
        Self::builder(s).readable().writable().try_build()
    }

    #[inline]
    #[deprecated(note = "Use Data::builder instead.", since = "0.11.1")]
    pub fn from_seekable_stream<S>(s: S) -> Result<Self, WrappedError<S>>
    where
        S: Read + Write + Seek + Send + 'data,
    {
        Self::builder(s)
            .readable()
            .writable()
            .seekable()
            .try_build()
    }

    /// Upstream documentation:
    /// [`gpgme_data_get_file_name`](https://www.gnupg.org/documentation/manuals/gpgme/Data-Buffer-Meta_002dData.html#index-gpgme_005fdata_005fget_005ffile_005fname)
    #[inline]
    pub fn filename(&self) -> Result<&str, Option<Utf8Error>> {
        self.filename_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    /// Upstream documentation:
    /// [`gpgme_data_get_file_name`](https://www.gnupg.org/documentation/manuals/gpgme/Data-Buffer-Meta_002dData.html#index-gpgme_005fdata_005fget_005ffile_005fname)
    #[inline]
    pub fn filename_raw(&self) -> Option<&CStr> {
        unsafe { utils::convert_raw_str(ffi::gpgme_data_get_file_name(self.as_raw())) }
    }

    /// Upstream documentation:
    /// [`gpgme_data_set_file_name`](https://www.gnupg.org/documentation/manuals/gpgme/Data-Buffer-Meta_002dData.html#index-gpgme_005fdata_005fset_005ffile_005fname)
    #[inline]
    pub fn clear_filename(&mut self) -> Result<()> {
        unsafe { convert_err(ffi::gpgme_data_set_file_name(self.as_raw(), ptr::null())) }
    }

    /// Upstream documentation:
    /// [`gpgme_data_set_file_name`](https://www.gnupg.org/documentation/manuals/gpgme/Data-Buffer-Meta_002dData.html#index-gpgme_005fdata_005fset_005ffile_005fname)
    #[inline]
    pub fn set_filename(&mut self, name: impl CStrArgument) -> Result<()> {
        let name = name.into_cstr();
        unsafe {
            convert_err(ffi::gpgme_data_set_file_name(
                self.as_raw(),
                name.as_ref().as_ptr(),
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_data_get_encoding`](https://www.gnupg.org/documentation/manuals/gpgme/Data-Buffer-Meta_002dData.html#index-gpgme_005fdata_005fget_005fencoding)
    #[inline]
    pub fn encoding(&self) -> Encoding {
        unsafe { Encoding::from_raw(ffi::gpgme_data_get_encoding(self.as_raw())) }
    }

    /// Upstream documentation:
    /// [`gpgme_data_set_encoding`](https://www.gnupg.org/documentation/manuals/gpgme/Data-Buffer-Meta_002dData.html#index-gpgme_005fdata_005fset_005fencoding)
    #[inline]
    pub fn set_encoding(&mut self, enc: Encoding) -> Result<()> {
        unsafe { convert_err(ffi::gpgme_data_set_encoding(self.as_raw(), enc.raw())) }
    }

    /// Upstream documentation:
    /// [`gpgme_data_set_flag`](https://www.gnupg.org/documentation/manuals/gpgme/Data-Buffer-Meta_002dData.html#index-gpgme_005fdata_005fset_005fflag)
    #[inline]
    pub fn set_flag(&mut self, name: impl CStrArgument, value: impl CStrArgument) -> Result<()> {
        let name = name.into_cstr();
        let value = value.into_cstr();
        unsafe {
            convert_err(ffi::gpgme_data_set_flag(
                self.as_raw(),
                name.as_ref().as_ptr(),
                value.as_ref().as_ptr(),
            ))
        }
    }

    /// Upstream documentation:
    /// [`gpgme_data_set_flag`](https://www.gnupg.org/documentation/manuals/gpgme/Data-Buffer-Meta_002dData.html#index-gpgme_005fdata_005fset_005fflag)
    #[inline]
    pub fn set_size_hint(&mut self, value: u64) -> Result<()> {
        self.set_flag(c"size-hint", value.to_string())
    }

    /// Upstream documentation:
    /// [`gpgme_data_identify`](https://www.gnupg.org/documentation/manuals/gpgme/Data-Buffer-Convenience.html#index-gpgme_005fdata_005fidentify)
    #[inline]
    pub fn identify(&mut self) -> Type {
        unsafe { Type::from_raw(ffi::gpgme_data_identify(self.as_raw(), 0)) }
    }

    /// Upstream documentation:
    /// [`gpgme_data_release_and_get_mem`](https://www.gnupg.org/documentation/manuals/gpgme/Destroying-Data-Buffers.html#index-gpgme_005fdata_005frelease_005fand_005fget_005fmem)
    #[inline]
    pub fn try_into_bytes(self) -> Option<Vec<u8>> {
        unsafe {
            let mut len = 0;
            let mem = ffi::gpgme_data_release_and_get_mem(self.into_raw(), &mut len);
            ptr::slice_from_raw_parts_mut(mem.cast::<u8>(), len)
                .as_mut()
                .map(|s| {
                    let r = s.to_vec();
                    ffi::gpgme_free(s.as_mut_ptr().cast());
                    r
                })
        }
    }
}

impl Read for Data<'_> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = unsafe {
            let (buf, len) = (buf.as_mut_ptr(), buf.len());
            ffi::gpgme_data_read(self.as_raw(), buf.cast(), len)
        };
        Ok(usize::try_from(result).map_err(|_| Error::last_os_error())?)
    }
}

impl Write for Data<'_> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let result =
            unsafe { ffi::gpgme_data_write(self.as_raw(), buf.as_ptr().cast(), buf.len()) };
        Ok(usize::try_from(result).map_err(|_| Error::last_os_error())?)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for Data<'_> {
    #[inline]
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let (off, whence) = match pos {
            io::SeekFrom::Start(off) => {
                (off.try_into().unwrap_or(gpgme_off_t::MAX), libc::SEEK_SET)
            }
            io::SeekFrom::End(off) => (off.value_into().unwrap_or_saturate(), libc::SEEK_END),
            io::SeekFrom::Current(off) => (off.value_into().unwrap_or_saturate(), libc::SEEK_CUR),
        };
        let result = unsafe { ffi::gpgme_data_seek(self.as_raw(), off, whence) };
        Ok(u64::try_from(result).map_err(|_| Error::last_os_error())?)
    }
}

struct CallbackWrapper<S> {
    cbs: ffi::gpgme_data_cbs,
    inner: S,
}

unsafe extern "C" fn read_callback<S: Read>(
    handle: *mut libc::c_void,
    buffer: *mut libc::c_void,
    size: libc::size_t,
) -> libc::ssize_t {
    let handle = handle.cast::<CallbackWrapper<S>>();
    let slice = slice::from_raw_parts_mut(buffer.cast::<u8>(), size);
    (*handle)
        .inner
        .read(slice)
        .map_err(Error::from)
        .and_then(|n| n.try_into().or(Err(Error::EOVERFLOW)))
        .unwrap_or_else(|err| {
            ffi::gpgme_err_set_errno(err.to_errno());
            -1
        })
}

unsafe extern "C" fn write_callback<S: Write>(
    handle: *mut libc::c_void,
    buffer: *const libc::c_void,
    size: libc::size_t,
) -> libc::ssize_t {
    let handle = handle.cast::<CallbackWrapper<S>>();
    let slice = slice::from_raw_parts(buffer.cast::<u8>(), size);
    (*handle)
        .inner
        .write(slice)
        .map_err(Error::from)
        .and_then(|n| n.try_into().or(Err(Error::EOVERFLOW)))
        .unwrap_or_else(|err| {
            ffi::gpgme_err_set_errno(err.to_errno());
            -1
        })
}

unsafe extern "C" fn seek_callback<S: Seek>(
    handle: *mut libc::c_void,
    offset: gpgme_off_t,
    whence: libc::c_int,
) -> gpgme_off_t {
    let handle = handle.cast::<CallbackWrapper<S>>();
    let pos = match whence {
        libc::SEEK_SET => io::SeekFrom::Start(offset.value_into().unwrap_or_saturate()),
        libc::SEEK_END => io::SeekFrom::End(offset.value_into().unwrap_or_saturate()),
        libc::SEEK_CUR => io::SeekFrom::Current(offset.value_into().unwrap_or_saturate()),
        _ => {
            ffi::gpgme_err_set_errno(Error::EINVAL.to_errno());
            return -1;
        }
    };
    (*handle)
        .inner
        .seek(pos)
        .map_err(Error::from)
        .and_then(|n| n.try_into().or(Err(Error::EOVERFLOW)))
        .unwrap_or_else(|err| {
            ffi::gpgme_err_set_errno(err.to_errno());
            -1
        })
}

unsafe extern "C" fn release_callback<S>(handle: *mut libc::c_void) {
    drop(Box::from_raw(handle.cast::<CallbackWrapper<S>>()));
}

/// A trait for converting compatible types into data objects.
pub trait IntoData<'a> {
    type Output: BorrowMut<Data<'a>>;

    fn into_data(self) -> Result<Self::Output>;
}

impl<'a> IntoData<'a> for &mut Data<'a> {
    type Output = Self;

    fn into_data(self) -> Result<Self> {
        Ok(self)
    }
}

impl<'a, T> IntoData<'a> for T
where
    T: TryInto<Data<'a>, Error = Error>,
{
    type Output = Data<'a>;

    fn into_data(self) -> Result<Self::Output> {
        self.try_into()
    }
}

impl<'a> TryFrom<&'a [u8]> for Data<'a> {
    type Error = Error;

    #[inline]
    fn try_from(value: &'a [u8]) -> Result<Self> {
        Self::from_buffer(value)
    }
}

impl<'a> TryFrom<&'a mut [u8]> for Data<'a> {
    type Error = Error;

    #[inline]
    fn try_from(value: &'a mut [u8]) -> Result<Self> {
        Self::builder(Cursor::new(value))
            .readable()
            .writable()
            .seekable()
            .try_build()
            .map_err(|e| e.error())
    }
}

impl<'a> TryFrom<&'a str> for Data<'a> {
    type Error = Error;

    #[inline]
    fn try_from(value: &'a str) -> Result<Self> {
        value.as_bytes().try_into()
    }
}

impl<'a> TryFrom<&'a Vec<u8>> for Data<'a> {
    type Error = Error;

    #[inline]
    fn try_from(value: &'a Vec<u8>) -> Result<Self> {
        value.as_slice().try_into()
    }
}

impl<'a> TryFrom<&'a mut Vec<u8>> for Data<'a> {
    type Error = Error;

    #[inline]
    fn try_from(value: &'a mut Vec<u8>) -> Result<Self> {
        Self::builder(Cursor::new(value))
            .readable()
            .writable()
            .seekable()
            .try_build()
            .map_err(|e| e.error())
    }
}

impl<'a> TryFrom<Vec<u8>> for Data<'a> {
    type Error = Error;

    #[inline]
    fn try_from(value: Vec<u8>) -> Result<Self> {
        Self::builder(Cursor::new(value))
            .readable()
            .writable()
            .seekable()
            .try_build()
            .map_err(|e| e.error())
    }
}

impl<'a> TryFrom<String> for Data<'a> {
    type Error = Error;

    #[inline]
    fn try_from(value: String) -> Result<Self> {
        value.into_bytes().try_into()
    }
}

impl<'a> TryFrom<&'a File> for Data<'a> {
    type Error = Error;

    #[inline]
    fn try_from(value: &'a File) -> Result<Self> {
        Self::builder(value)
            .readable()
            .writable()
            .seekable()
            .try_build()
            .map_err(|e| e.error())
    }
}

impl<'a> TryFrom<&'a mut File> for Data<'a> {
    type Error = Error;

    #[inline]
    fn try_from(value: &'a mut File) -> Result<Self> {
        Self::try_from(&*value)
    }
}

impl<'a> TryFrom<File> for Data<'a> {
    type Error = Error;

    #[inline]
    fn try_from(value: File) -> Result<Self> {
        Self::builder(value)
            .readable()
            .writable()
            .seekable()
            .try_build()
            .map_err(|e| e.error())
    }
}

impl<'a> TryFrom<io::Stdout> for Data<'a> {
    type Error = Error;

    #[inline]
    fn try_from(value: io::Stdout) -> Result<Self> {
        Self::builder(value)
            .writable()
            .try_build()
            .map_err(|e| e.error())
    }
}

impl<'a> TryFrom<io::Stderr> for Data<'a> {
    type Error = Error;

    #[inline]
    fn try_from(value: io::Stderr) -> Result<Self> {
        Self::builder(value)
            .writable()
            .try_build()
            .map_err(|e| e.error())
    }
}

impl<'a> TryFrom<io::Stdin> for Data<'a> {
    type Error = Error;

    #[inline]
    fn try_from(value: io::Stdin) -> Result<Self> {
        Self::builder(value)
            .readable()
            .try_build()
            .map_err(|e| e.error())
    }
}

#[cfg(unix)]
impl<'a> TryFrom<BorrowedFd<'a>> for Data<'a> {
    type Error = Error;

    #[inline]
    fn try_from(value: BorrowedFd<'a>) -> Result<Self> {
        Data::from_borrowed_fd(value)
    }
}

/// A struct that helps with creating a [`Data`] object from a wrapped object
/// that implements [`Read`]/[`Write`]/[`Seek`].
#[must_use]
#[derive(Clone)]
pub struct DataBuilder<T> {
    inner: T,
    cbs: ffi::gpgme_data_cbs,
}

impl<T: Send> DataBuilder<T> {
    /// Returns a new builder wrapping the provided value.
    #[inline]
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            cbs: ffi::gpgme_data_cbs {
                read: None,
                write: None,
                seek: None,
                release: Some(release_callback::<T>),
            },
        }
    }

    /// Enables reading from the wrapped object.
    #[inline]
    pub fn readable(mut self) -> Self
    where
        T: Read,
    {
        self.cbs.read = Some(read_callback::<T>);
        self
    }

    /// Enables writing to the wrapped object.
    #[inline]
    pub fn writable(mut self) -> Self
    where
        T: Write,
    {
        self.cbs.write = Some(write_callback::<T>);
        self
    }

    /// Enables seeking within the wrapped object.
    #[inline]
    pub fn seekable(mut self) -> Self
    where
        T: Seek,
    {
        self.cbs.seek = Some(seek_callback::<T>);
        self
    }

    /// Attempts to build a new [`Data`] object using the wrapped
    /// value as a backing source/sink.
    #[inline]
    pub fn try_build<'a>(self) -> Result<Data<'a>, WrappedError<T>>
    where
        T: 'a,
    {
        unsafe { Data::from_callbacks(self.cbs, self.inner) }
    }
}

impl<T> fmt::Debug for DataBuilder<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataBuilder")
            .field("inner", &self.inner)
            .field("readable", &self.cbs.read.is_some())
            .field("writable", &self.cbs.write.is_some())
            .field("seekable", &self.cbs.seek.is_some())
            .finish()
    }
}
