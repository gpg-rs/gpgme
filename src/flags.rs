#![allow(trivial_numeric_casts)]
use std::{ffi::CStr, fmt, str::Utf8Error};

use bitflags::bitflags;
use ffi;
use libc;

bitflags! {
    pub struct KeyListMode: ffi::gpgme_keylist_mode_t {
        const LOCAL = ffi::GPGME_KEYLIST_MODE_LOCAL;
        const EXTERN = ffi::GPGME_KEYLIST_MODE_EXTERN;
        const SIGS = ffi::GPGME_KEYLIST_MODE_SIGS;
        const SIG_NOTATIONS = ffi::GPGME_KEYLIST_MODE_SIG_NOTATIONS;
        const WITH_SECRET = ffi::GPGME_KEYLIST_MODE_WITH_SECRET;
        const WITH_TOFU = ffi::GPGME_KEYLIST_MODE_WITH_TOFU;
        const EPHEMERAL = ffi::GPGME_KEYLIST_MODE_EPHEMERAL;
        const VALIDATE = ffi::GPGME_KEYLIST_MODE_VALIDATE;
        const LOCATE = ffi::GPGME_KEYLIST_MODE_LOCATE;
    }
}

bitflags! {
    pub struct CreateKeyFlags: libc::c_uint {
        const SIGN = ffi::GPGME_CREATE_SIGN;
        const ENCR = ffi::GPGME_CREATE_ENCR;
        const CERT = ffi::GPGME_CREATE_CERT;
        const AUTH = ffi::GPGME_CREATE_AUTH;
        const NOPASSWD = ffi::GPGME_CREATE_NOPASSWD;
        const SELFSIGNED = ffi::GPGME_CREATE_SELFSIGNED;
        const NOSTORE = ffi::GPGME_CREATE_NOSTORE;
        const WANTPUB = ffi::GPGME_CREATE_WANTPUB;
        const WANTSEC = ffi::GPGME_CREATE_WANTSEC;
        const FORCE = ffi::GPGME_CREATE_FORCE;
        const NOEXPIRE = ffi::GPGME_CREATE_NOEXPIRE;
    }
}

bitflags! {
    pub struct DeleteKeyFlags: libc::c_uint {
        const ALLOW_SECRET = ffi::GPGME_DELETE_ALLOW_SECRET;
        const FORCE = ffi::GPGME_DELETE_FORCE;
    }
}

bitflags! {
    pub struct KeySigningFlags: libc::c_uint {
        const LOCAL = ffi::GPGME_KEYSIGN_LOCAL;
        const LFSEP = ffi::GPGME_KEYSIGN_LFSEP;
        const NOEXPIRE = ffi::GPGME_KEYSIGN_NOEXPIRE;
    }
}

bitflags! {
    pub struct ImportFlags: libc::c_uint {
        const NEW = ffi::GPGME_IMPORT_NEW;
        const UID = ffi::GPGME_IMPORT_UID;
        const SIG = ffi::GPGME_IMPORT_SIG;
        const SUBKEY = ffi::GPGME_IMPORT_SUBKEY;
        const SECRET = ffi::GPGME_IMPORT_SECRET;
    }
}

bitflags! {
    pub struct ExportMode: ffi::gpgme_export_mode_t {
        const EXTERN = ffi::GPGME_EXPORT_MODE_EXTERN;
        const MINIMAL = ffi::GPGME_EXPORT_MODE_MINIMAL;
        const SECRET = ffi::GPGME_EXPORT_MODE_SECRET;
        const RAW = ffi::GPGME_EXPORT_MODE_RAW;
        const PKCS12 = ffi::GPGME_EXPORT_MODE_PKCS12;
    }
}

bitflags! {
    pub struct EncryptFlags: ffi::gpgme_encrypt_flags_t {
        const ALWAYS_TRUST = ffi::GPGME_ENCRYPT_ALWAYS_TRUST;
        const NO_ENCRYPT_TO = ffi::GPGME_ENCRYPT_NO_ENCRYPT_TO;
        const PREPARE = ffi::GPGME_ENCRYPT_PREPARE;
        const EXPECT_SIGN = ffi::GPGME_ENCRYPT_EXPECT_SIGN;
        const NO_COMPRESS= ffi::GPGME_ENCRYPT_NO_COMPRESS;
        const SYMMETRIC = ffi::GPGME_ENCRYPT_SYMMETRIC;
        const THROW_KEYIDS = ffi::GPGME_ENCRYPT_THROW_KEYIDS;
        const WRAP = ffi::GPGME_ENCRYPT_WRAP;
        const WANT_ADDRESS = ffi::GPGME_ENCRYPT_WANT_ADDRESS;
    }
}

bitflags! {
    pub struct DecryptFlags: ffi::gpgme_decrypt_flags_t {
        const VERIFY = ffi::GPGME_DECRYPT_VERIFY;
        const UNWRAP = ffi::GPGME_DECRYPT_UNWRAP;
    }
}

bitflags! {
    pub struct SignatureSummary: ffi::gpgme_sigsum_t {
        const VALID = ffi::GPGME_SIGSUM_VALID;
        const GREEN = ffi::GPGME_SIGSUM_GREEN;
        const RED = ffi::GPGME_SIGSUM_RED;
        const KEY_REVOKED = ffi::GPGME_SIGSUM_KEY_REVOKED;
        const KEY_EXPIRED = ffi::GPGME_SIGSUM_KEY_EXPIRED;
        const SIG_EXPIRED = ffi::GPGME_SIGSUM_SIG_EXPIRED;
        const KEY_MISSING = ffi::GPGME_SIGSUM_KEY_MISSING;
        const CRL_MISSING = ffi::GPGME_SIGSUM_CRL_MISSING;
        const CRL_TOO_OLD = ffi::GPGME_SIGSUM_CRL_TOO_OLD;
        const BAD_POLICY = ffi::GPGME_SIGSUM_BAD_POLICY;
        const SYS_ERROR = ffi::GPGME_SIGSUM_SYS_ERROR;
        const TOFU_CONFLICT = ffi::GPGME_SIGSUM_TOFU_CONFLICT;
    }
}

bitflags! {
    pub struct SignatureNotationFlags: ffi::gpgme_sig_notation_flags_t {
        const HUMAN_READABLE = ffi::GPGME_SIG_NOTATION_HUMAN_READABLE;
        const CRITICAL = ffi::GPGME_SIG_NOTATION_CRITICAL;
    }
}

bitflags! {
    pub struct AuditLogFlags: libc::c_uint {
        const DEFAULT = ffi::GPGME_AUDITLOG_DEFAULT;
        const HTML = ffi::GPGME_AUDITLOG_HTML;
        const DIAG = ffi::GPGME_AUDITLOG_DIAG;
        const WITH_HELP = ffi::GPGME_AUDITLOG_WITH_HELP;
    }
}

ffi_enum_wrapper! {
    pub enum KeyOrigin: ffi::gpgme_keyorg_t {
        Unknown = ffi::GPGME_KEYORG_UNKNOWN,
        KeyServer = ffi::GPGME_KEYORG_KS,
        Dane = ffi::GPGME_KEYORG_DANE,
        Wkd = ffi::GPGME_KEYORG_WKD,
        Url = ffi::GPGME_KEYORG_URL,
        File = ffi::GPGME_KEYORG_FILE,
        Self_ = ffi::GPGME_KEYORG_SELF,
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name().unwrap_or("Unknown"))
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name().unwrap_or("Unknown"))
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
