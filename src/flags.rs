#![allow(trivial_numeric_casts)]
use std::ffi::CStr;
use std::fmt;
use std::str::Utf8Error;

use libc;
use ffi;

bitflags! {
    pub struct KeyListMode: ffi::gpgme_keylist_mode_t {
        const KEY_LIST_MODE_LOCAL = ffi::GPGME_KEYLIST_MODE_LOCAL;
        const KEY_LIST_MODE_EXTERN = ffi::GPGME_KEYLIST_MODE_EXTERN;
        const KEY_LIST_MODE_SIGS = ffi::GPGME_KEYLIST_MODE_SIGS;
        const KEY_LIST_MODE_SIG_NOTATIONS = ffi::GPGME_KEYLIST_MODE_SIG_NOTATIONS;
        const KEY_LIST_MODE_WITH_SECRET = ffi::GPGME_KEYLIST_MODE_WITH_SECRET;
        const KEY_LIST_MODE_WITH_TOFU = ffi::GPGME_KEYLIST_MODE_WITH_TOFU;
        const KEY_LIST_MODE_EPHEMERAL = ffi::GPGME_KEYLIST_MODE_EPHEMERAL;
        const KEY_LIST_MODE_VALIDATE = ffi::GPGME_KEYLIST_MODE_VALIDATE;
    }
}

bitflags! {
    pub struct CreateKeyFlags: libc::c_uint {
        const CREATE_SIGN = ffi::GPGME_CREATE_SIGN;
        const CREATE_ENCR = ffi::GPGME_CREATE_ENCR;
        const CREATE_CERT = ffi::GPGME_CREATE_CERT;
        const CREATE_AUTH = ffi::GPGME_CREATE_AUTH;
        const CREATE_NOPASSWD = ffi::GPGME_CREATE_NOPASSWD;
        const CREATE_SELFSIGNED = ffi::GPGME_CREATE_SELFSIGNED;
        const CREATE_NOSTORE = ffi::GPGME_CREATE_NOSTORE;
        const CREATE_WANTPUB = ffi::GPGME_CREATE_WANTPUB;
        const CREATE_WANTSEC = ffi::GPGME_CREATE_WANTSEC;
        const CREATE_FORCE = ffi::GPGME_CREATE_FORCE;
        const CREATE_NOEXPIRE = ffi::GPGME_CREATE_NOEXPIRE;
    }
}

bitflags! {
    pub struct KeySigningFlags: libc::c_uint {
        const KEY_SIGN_LOCAL = ffi::GPGME_KEYSIGN_LOCAL;
        const KEY_SIGN_LFSEP = ffi::GPGME_KEYSIGN_LFSEP;
        const KEY_SIGN_NOEXPIRE = ffi::GPGME_KEYSIGN_NOEXPIRE;
    }
}

bitflags! {
    pub struct ImportFlags: libc::c_uint {
        const IMPORT_NEW = ffi::GPGME_IMPORT_NEW;
        const IMPORT_UID = ffi::GPGME_IMPORT_UID;
        const IMPORT_SIG = ffi::GPGME_IMPORT_SIG;
        const IMPORT_SUBKEY = ffi::GPGME_IMPORT_SUBKEY;
        const IMPORT_SECRET = ffi::GPGME_IMPORT_SECRET;
    }
}

bitflags! {
    pub struct ExportMode: ffi::gpgme_export_mode_t {
        const EXPORT_EXTERN = ffi::GPGME_EXPORT_MODE_EXTERN;
        const EXPORT_MINIMAL = ffi::GPGME_EXPORT_MODE_MINIMAL;
        const EXPORT_SECRET = ffi::GPGME_EXPORT_MODE_SECRET;
        const EXPORT_RAW = ffi::GPGME_EXPORT_MODE_RAW;
        const EXPORT_PKCS12 = ffi::GPGME_EXPORT_MODE_PKCS12;
    }
}

bitflags! {
    pub struct EncryptFlags: ffi::gpgme_encrypt_flags_t {
        const ENCRYPT_ALWAYS_TRUST = ffi::GPGME_ENCRYPT_ALWAYS_TRUST;
        const ENCRYPT_NO_ENCRYPT_TO = ffi::GPGME_ENCRYPT_NO_ENCRYPT_TO;
        const ENCRYPT_PREPARE = ffi::GPGME_ENCRYPT_PREPARE;
        const ENCRYPT_EXPECT_SIGN = ffi::GPGME_ENCRYPT_EXPECT_SIGN;
        const ENCRYPT_NO_COMPRESS= ffi::GPGME_ENCRYPT_NO_COMPRESS;
        const ENCRYPT_SYMMETRIC = ffi::GPGME_ENCRYPT_SYMMETRIC;
        const ENCRYPT_THROW_KEYIDS = ffi::GPGME_ENCRYPT_THROW_KEYIDS;
        const ENCRYPT_WRAP = ffi::GPGME_ENCRYPT_WRAP;
    }
}

bitflags! {
    pub struct DecryptFlags: ffi::gpgme_decrypt_flags_t {
        const DECRYPT_VERIFY = ffi::GPGME_DECRYPT_VERIFY;
        const DECRYPT_UNWRAP = ffi::GPGME_DECRYPT_UNWRAP;
    }
}

bitflags! {
    pub struct SignatureSummary: ffi::gpgme_sigsum_t {
        const SIGNATURE_VALID = ffi::GPGME_SIGSUM_VALID;
        const SIGNATURE_GREEN = ffi::GPGME_SIGSUM_GREEN;
        const SIGNATURE_RED = ffi::GPGME_SIGSUM_RED;
        const SIGNATURE_KEY_REVOKED = ffi::GPGME_SIGSUM_KEY_REVOKED;
        const SIGNATURE_KEY_EXPIRED = ffi::GPGME_SIGSUM_KEY_EXPIRED;
        const SIGNATURE_SIG_EXPIRED = ffi::GPGME_SIGSUM_SIG_EXPIRED;
        const SIGNATURE_KEY_MISSING = ffi::GPGME_SIGSUM_KEY_MISSING;
        const SIGNATURE_CRL_MISSING = ffi::GPGME_SIGSUM_CRL_MISSING;
        const SIGNATURE_CRL_TOO_OLD = ffi::GPGME_SIGSUM_CRL_TOO_OLD;
        const SIGNATURE_BAD_POLICY = ffi::GPGME_SIGSUM_BAD_POLICY;
        const SIGNATURE_SYS_ERROR = ffi::GPGME_SIGSUM_SYS_ERROR;
        const SIGNATURE_TOFU_CONFLICT = ffi::GPGME_SIGSUM_TOFU_CONFLICT;
    }
}

bitflags! {
    pub struct SignatureNotationFlags: ffi::gpgme_sig_notation_flags_t {
        const NOTATION_HUMAN_READABLE = ffi::GPGME_SIG_NOTATION_HUMAN_READABLE;
        const NOTATION_CRITICAL = ffi::GPGME_SIG_NOTATION_CRITICAL;
    }
}

bitflags! {
    pub struct AuditLogFlags: libc::c_uint {
        const AUDIT_LOG_HTML = ffi::GPGME_AUDITLOG_HTML;
        const AUDIT_LOG_WITH_HELP = ffi::GPGME_AUDITLOG_WITH_HELP;
    }
}

ffi_enum_wrapper! {
    pub enum SignMode: ffi::gpgme_sig_mode_t {
        Normal = ffi::GPGME_SIG_MODE_NORMAL,
        Detached = ffi::GPGME_SIG_MODE_DETACH,
        Clear = ffi::GPGME_SIG_MODE_CLEAR,
    }
}

ffi_enum_wrapper! {
    pub enum KeyAlgorithm: ffi::gpgme_pubkey_algo_t {
        Rsa = ffi::GPGME_PK_RSA,
        RsaEncrypt = ffi::GPGME_PK_RSA_E,
        RsaSign = ffi::GPGME_PK_RSA_S,
        ElgamalEncrypt = ffi::GPGME_PK_ELG_E,
        Dsa = ffi::GPGME_PK_DSA,
        Ecc = ffi::GPGME_PK_ECC,
        Elgamal = ffi::GPGME_PK_ELG,
        Ecdsa = ffi::GPGME_PK_ECDSA,
        Ecdh = ffi::GPGME_PK_ECDH,
        Eddsa = ffi::GPGME_PK_EDDSA,
    }
}

impl KeyAlgorithm {
    #[inline]
    pub fn name(&self) -> Result<&'static str, Option<Utf8Error>> {
        self.name_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn name_raw(&self) -> Option<&'static CStr> {
        unsafe {
            ffi::gpgme_pubkey_algo_name(self.raw())
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }
}

impl fmt::Display for KeyAlgorithm {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name().unwrap_or("Unknown"))
    }
}

ffi_enum_wrapper! {
    pub enum HashAlgorithm: ffi::gpgme_hash_algo_t {
        None = ffi::GPGME_MD_NONE,
        Md2 = ffi::GPGME_MD_MD2,
        Md4 = ffi::GPGME_MD_MD4,
        Md5 = ffi::GPGME_MD_MD5,
        Sha1 = ffi::GPGME_MD_SHA1,
        Sha224 = ffi::GPGME_MD_SHA224,
        Sha256 = ffi::GPGME_MD_SHA256,
        Sha384 = ffi::GPGME_MD_SHA384,
        Sha512 = ffi::GPGME_MD_SHA512,
        RipeMd160 = ffi::GPGME_MD_RMD160,
        Tiger = ffi::GPGME_MD_TIGER,
        Haval = ffi::GPGME_MD_HAVAL,
        Crc32 = ffi::GPGME_MD_CRC32,
        Crc32Rfc1510 = ffi::GPGME_MD_CRC32_RFC1510,
        CrC24Rfc2440 = ffi::GPGME_MD_CRC24_RFC2440,
    }
}

impl HashAlgorithm {
    #[inline]
    pub fn name(&self) -> Result<&'static str, Option<Utf8Error>> {
        self.name_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn name_raw(&self) -> Option<&'static CStr> {
        unsafe {
            ffi::gpgme_hash_algo_name(self.raw())
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }
}

impl fmt::Display for HashAlgorithm {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name().unwrap_or("Unknown"))
    }
}

ffi_enum_wrapper! {
    pub enum PinentryMode: ffi::gpgme_pinentry_mode_t {
        Default = ffi::GPGME_PINENTRY_MODE_DEFAULT,
        Ask = ffi::GPGME_PINENTRY_MODE_ASK,
        Cancel = ffi::GPGME_PINENTRY_MODE_CANCEL,
        Error = ffi::GPGME_PINENTRY_MODE_ERROR,
        Loopback = ffi::GPGME_PINENTRY_MODE_LOOPBACK,
    }
}
