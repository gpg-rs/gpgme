extern crate libc;
extern crate libgpg_error_sys;

use libc::{c_int, c_char, c_uint, size_t, c_uchar, c_void, c_ushort, c_long, c_ulong};

pub use libgpg_error_sys::gpg_err_source_t as gpgme_err_source_t;
pub use libgpg_error_sys::gpg_err_code_t as gpgme_err_code_t;

pub use libgpg_error_sys::gpg_err_source_t::*;
pub use libgpg_error_sys::gpg_err_code_t::*;

enum_from_primitive! {
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub enum gpgme_data_encoding_t {
        GPGME_DATA_ENCODING_NONE   = 0,
        GPGME_DATA_ENCODING_BINARY = 1,
        GPGME_DATA_ENCODING_BASE64 = 2,
        GPGME_DATA_ENCODING_ARMOR  = 3,
        GPGME_DATA_ENCODING_URL    = 4,
        GPGME_DATA_ENCODING_URLESC = 5,
        GPGME_DATA_ENCODING_URL0   = 6
    }
}
pub use self::gpgme_data_encoding_t::*;

enum_from_primitive! {
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub enum gpgme_data_type_t {
        GPGME_DATA_TYPE_INVALID      = 0,
        GPGME_DATA_TYPE_UNKNOWN      = 1,
        GPGME_DATA_TYPE_PGP_SIGNED   = 0x10,
        GPGME_DATA_TYPE_PGP_OTHER    = 0x12,
        GPGME_DATA_TYPE_PGP_KEY      = 0x13,
        GPGME_DATA_TYPE_CMS_SIGNED   = 0x20,
        GPGME_DATA_TYPE_CMS_ENCRYPTED= 0x21,
        GPGME_DATA_TYPE_CMS_OTHER    = 0x22,
        GPGME_DATA_TYPE_X509_CERT    = 0x23,
        GPGME_DATA_TYPE_PKCS12       = 0x24,
    }
}
pub use self::gpgme_data_type_t::*;

enum_from_primitive! {
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub enum gpgme_pubkey_algo_t {
        GPGME_PK_RSA   = 1,
        GPGME_PK_RSA_E = 2,
        GPGME_PK_RSA_S = 3,
        GPGME_PK_ELG_E = 16,
        GPGME_PK_DSA   = 17,
        GPGME_PK_ELG   = 20,
        GPGME_PK_ECDSA = 301,
        GPGME_PK_ECDH  = 302
    }
}
pub use self::gpgme_pubkey_algo_t::*;

enum_from_primitive! {
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub enum gpgme_hash_algo_t {
        GPGME_MD_NONE          = 0,
        GPGME_MD_MD5           = 1,
        GPGME_MD_SHA1          = 2,
        GPGME_MD_RMD160        = 3,
        GPGME_MD_MD2           = 5,
        GPGME_MD_TIGER         = 6,
        GPGME_MD_HAVAL         = 7,
        GPGME_MD_SHA256        = 8,
        GPGME_MD_SHA384        = 9,
        GPGME_MD_SHA512        = 10,
        GPGME_MD_MD4           = 301,
        GPGME_MD_CRC32	   = 302,
        GPGME_MD_CRC32_RFC1510 = 303,
        GPGME_MD_CRC24_RFC2440 = 304
    }
}
pub use self::gpgme_hash_algo_t::*;

enum_from_primitive! {
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub enum gpgme_sig_stat_t {
        GPGME_SIG_STAT_NONE  = 0,
        GPGME_SIG_STAT_GOOD  = 1,
        GPGME_SIG_STAT_BAD   = 2,
        GPGME_SIG_STAT_NOKEY = 3,
        GPGME_SIG_STAT_NOSIG = 4,
        GPGME_SIG_STAT_ERROR = 5,
        GPGME_SIG_STAT_DIFF  = 6,
        GPGME_SIG_STAT_GOOD_EXP = 7,
        GPGME_SIG_STAT_GOOD_EXPKEY = 8
    }
}
pub use self::gpgme_sig_stat_t::*;

enum_from_primitive! {
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub enum gpgme_sig_mode_t {
        GPGME_SIG_MODE_NORMAL = 0,
        GPGME_SIG_MODE_DETACH = 1,
        GPGME_SIG_MODE_CLEAR  = 2
    }
}
pub use self::gpgme_sig_mode_t::*;

enum_from_primitive! {
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub enum gpgme_attr_t {
        GPGME_ATTR_KEYID        = 1,
        GPGME_ATTR_FPR          = 2,
        GPGME_ATTR_ALGO         = 3,
        GPGME_ATTR_LEN          = 4,
        GPGME_ATTR_CREATED      = 5,
        GPGME_ATTR_EXPIRE       = 6,
        GPGME_ATTR_OTRUST       = 7,
        GPGME_ATTR_USERID       = 8,
        GPGME_ATTR_NAME         = 9,
        GPGME_ATTR_EMAIL        = 10,
        GPGME_ATTR_COMMENT      = 11,
        GPGME_ATTR_VALIDITY     = 12,
        GPGME_ATTR_LEVEL        = 13,
        GPGME_ATTR_TYPE         = 14,
        GPGME_ATTR_IS_SECRET    = 15,
        GPGME_ATTR_KEY_REVOKED  = 16,
        GPGME_ATTR_KEY_INVALID  = 17,
        GPGME_ATTR_UID_REVOKED  = 18,
        GPGME_ATTR_UID_INVALID  = 19,
        GPGME_ATTR_KEY_CAPS     = 20,
        GPGME_ATTR_CAN_ENCRYPT  = 21,
        GPGME_ATTR_CAN_SIGN     = 22,
        GPGME_ATTR_CAN_CERTIFY  = 23,
        GPGME_ATTR_KEY_EXPIRED  = 24,
        GPGME_ATTR_KEY_DISABLED = 25,
        GPGME_ATTR_SERIAL       = 26,
        GPGME_ATTR_ISSUER       = 27,
        GPGME_ATTR_CHAINID      = 28,
        GPGME_ATTR_SIG_STATUS   = 29,
        GPGME_ATTR_ERRTOK       = 30,
        GPGME_ATTR_SIG_SUMMARY  = 31,
        GPGME_ATTR_SIG_CLASS    = 32
    }
}
pub use self::gpgme_attr_t::*;

enum_from_primitive! {
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub enum gpgme_validity_t {
        GPGME_VALIDITY_UNKNOWN   = 0,
        GPGME_VALIDITY_UNDEFINED = 1,
        GPGME_VALIDITY_NEVER     = 2,
        GPGME_VALIDITY_MARGINAL  = 3,
        GPGME_VALIDITY_FULL      = 4,
        GPGME_VALIDITY_ULTIMATE  = 5
    }
}
pub use self::gpgme_validity_t::*;

enum_from_primitive! {
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub enum gpgme_protocol_t {
        GPGME_PROTOCOL_OpenPGP = 0,
        GPGME_PROTOCOL_CMS     = 1,
        GPGME_PROTOCOL_GPGCONF = 2,
        GPGME_PROTOCOL_ASSUAN  = 3,
        GPGME_PROTOCOL_G13     = 4,
        GPGME_PROTOCOL_UISERVER= 5,
        GPGME_PROTOCOL_DEFAULT = 254,
        GPGME_PROTOCOL_UNKNOWN = 255
    }
}
pub use self::gpgme_protocol_t::*;

pub type gpgme_keylist_mode_t = c_uint;
pub const GPGME_KEYLIST_MODE_LOCAL: gpgme_keylist_mode_t = 1;
pub const GPGME_KEYLIST_MODE_EXTERN: gpgme_keylist_mode_t = 2;
pub const GPGME_KEYLIST_MODE_SIGS: gpgme_keylist_mode_t = 4;
pub const GPGME_KEYLIST_MODE_SIG_NOTATIONS: gpgme_keylist_mode_t = 8;
pub const GPGME_KEYLIST_MODE_EPHEMERAL: gpgme_keylist_mode_t = 128;
pub const GPGME_KEYLIST_MODE_VALIDATE: gpgme_keylist_mode_t = 256;

enum_from_primitive! {
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub enum gpgme_pinentry_mode_t {
        GPGME_PINENTRY_MODE_DEFAULT  = 0,
        GPGME_PINENTRY_MODE_ASK      = 1,
        GPGME_PINENTRY_MODE_CANCEL   = 2,
        GPGME_PINENTRY_MODE_ERROR    = 3,
        GPGME_PINENTRY_MODE_LOOPBACK = 4
    }
}
pub use self::gpgme_pinentry_mode_t::*;

pub type gpgme_export_mode_t = c_uint;
pub const GPGME_EXPORT_MODE_EXTERN: gpgme_export_mode_t = 2;
pub const GPGME_EXPORT_MODE_MINIMAL: gpgme_export_mode_t = 4;

pub const GPGME_AUDITLOG_HTML: isize = 1;
pub const GPGME_AUDITLOG_WITH_HELP: isize = 128;

pub type gpgme_sig_notation_flags_t = c_uint;
pub const GPGME_SIG_NOTATION_HUMAN_READABLE: gpgme_sig_notation_flags_t = 1;
pub const GPGME_SIG_NOTATION_CRITICAL: gpgme_sig_notation_flags_t = 2;

enum_from_primitive! {
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub enum gpgme_status_code_t {
        GPGME_STATUS_EOF = 0,

        GPGME_STATUS_ENTER = 1,
        GPGME_STATUS_LEAVE = 2,
        GPGME_STATUS_ABORT = 3,

        GPGME_STATUS_GOODSIG = 4,
        GPGME_STATUS_BADSIG = 5,
        GPGME_STATUS_ERRSIG = 6,

        GPGME_STATUS_BADARMOR = 7,

        GPGME_STATUS_RSA_OR_IDEA = 8,
        GPGME_STATUS_KEYEXPIRED = 9,
        GPGME_STATUS_KEYREVOKED = 10,

        GPGME_STATUS_TRUST_UNDEFINED = 11,
        GPGME_STATUS_TRUST_NEVER = 12,
        GPGME_STATUS_TRUST_MARGINAL = 13,
        GPGME_STATUS_TRUST_FULLY = 14,
        GPGME_STATUS_TRUST_ULTIMATE = 15,

        GPGME_STATUS_SHM_INFO = 16,
        GPGME_STATUS_SHM_GET = 17,
        GPGME_STATUS_SHM_GET_BOOL = 18,
        GPGME_STATUS_SHM_GET_HIDDEN = 19,

        GPGME_STATUS_NEED_PASSPHRASE = 20,
        GPGME_STATUS_VALIDSIG = 21,
        GPGME_STATUS_SIG_ID = 22,
        GPGME_STATUS_ENC_TO = 23,
        GPGME_STATUS_NODATA = 24,
        GPGME_STATUS_BAD_PASSPHRASE = 25,
        GPGME_STATUS_NO_PUBKEY = 26,
        GPGME_STATUS_NO_SECKEY = 27,
        GPGME_STATUS_NEED_PASSPHRASE_SYM = 28,
        GPGME_STATUS_DECRYPTION_FAILED = 29,
        GPGME_STATUS_DECRYPTION_OKAY = 30,
        GPGME_STATUS_MISSING_PASSPHRASE = 31,
        GPGME_STATUS_GOOD_PASSPHRASE = 32,
        GPGME_STATUS_GOODMDC = 33,
        GPGME_STATUS_BADMDC = 34,
        GPGME_STATUS_ERRMDC = 35,
        GPGME_STATUS_IMPORTED = 36,
        GPGME_STATUS_IMPORT_OK = 37,
        GPGME_STATUS_IMPORT_PROBLEM = 38,
        GPGME_STATUS_IMPORT_RES = 39,
        GPGME_STATUS_FILE_START = 40,
        GPGME_STATUS_FILE_DONE = 41,
        GPGME_STATUS_FILE_ERROR = 42,

        GPGME_STATUS_BEGIN_DECRYPTION = 43,
        GPGME_STATUS_END_DECRYPTION = 44,
        GPGME_STATUS_BEGIN_ENCRYPTION = 45,
        GPGME_STATUS_END_ENCRYPTION = 46,

        GPGME_STATUS_DELETE_PROBLEM = 47,
        GPGME_STATUS_GET_BOOL = 48,
        GPGME_STATUS_GET_LINE = 49,
        GPGME_STATUS_GET_HIDDEN = 50,
        GPGME_STATUS_GOT_IT = 51,
        GPGME_STATUS_PROGRESS = 52,
        GPGME_STATUS_SIG_CREATED = 53,
        GPGME_STATUS_SESSION_KEY = 54,
        GPGME_STATUS_NOTATION_NAME = 55,
        GPGME_STATUS_NOTATION_DATA = 56,
        GPGME_STATUS_POLICY_URL = 57,
        GPGME_STATUS_BEGIN_STREAM = 58,
        GPGME_STATUS_END_STREAM = 59,
        GPGME_STATUS_KEY_CREATED = 60,
        GPGME_STATUS_USERID_HINT = 61,
        GPGME_STATUS_UNEXPECTED = 62,
        GPGME_STATUS_INV_RECP = 63,
        GPGME_STATUS_NO_RECP = 64,
        GPGME_STATUS_ALREADY_SIGNED = 65,
        GPGME_STATUS_SIGEXPIRED = 66,
        GPGME_STATUS_EXPSIG = 67,
        GPGME_STATUS_EXPKEYSIG = 68,
        GPGME_STATUS_TRUNCATED = 69,
        GPGME_STATUS_ERROR = 70,
        GPGME_STATUS_NEWSIG = 71,
        GPGME_STATUS_REVKEYSIG = 72,
        GPGME_STATUS_SIG_SUBPACKET = 73,
        GPGME_STATUS_NEED_PASSPHRASE_PIN = 74,
        GPGME_STATUS_SC_OP_FAILURE = 75,
        GPGME_STATUS_SC_OP_SUCCESS = 76,
        GPGME_STATUS_CARDCTRL = 77,
        GPGME_STATUS_BACKUP_KEY_CREATED = 78,
        GPGME_STATUS_PKA_TRUST_BAD = 79,
        GPGME_STATUS_PKA_TRUST_GOOD = 80,
        GPGME_STATUS_PLAINTEXT = 81,
        GPGME_STATUS_INV_SGNR = 82,
        GPGME_STATUS_NO_SGNR = 83,
        GPGME_STATUS_SUCCESS = 84,
        GPGME_STATUS_DECRYPTION_INFO = 85
    }
}
pub use self::gpgme_status_code_t::*;

pub const GPGME_INCLUDE_CERTS_DEFAULT: c_int = -256;

enum_from_primitive! {
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub enum gpgme_event_io_t {
        GPGME_EVENT_START,
        GPGME_EVENT_DONE,
        GPGME_EVENT_NEXT_KEY,
        GPGME_EVENT_NEXT_TRUSTITEM
    }
}
pub use self::gpgme_event_io_t::*;

pub type gpgme_encrypt_flags_t = c_uint;
pub const GPGME_ENCRYPT_ALWAYS_TRUST: gpgme_encrypt_flags_t = 1;
pub const GPGME_ENCRYPT_NO_ENCRYPT_TO: gpgme_encrypt_flags_t = 2;
pub const GPGME_ENCRYPT_PREPARE: gpgme_encrypt_flags_t = 4;
pub const GPGME_ENCRYPT_EXPECT_SIGN: gpgme_encrypt_flags_t = 8;


pub type gpgme_sigsum_t = c_uint;
pub const GPGME_SIGSUM_VALID: gpgme_sigsum_t = 0x0001;
pub const GPGME_SIGSUM_GREEN: gpgme_sigsum_t = 0x0002;
pub const GPGME_SIGSUM_RED:  gpgme_sigsum_t = 0x0004;
pub const GPGME_SIGSUM_KEY_REVOKED: gpgme_sigsum_t = 0x0010;
pub const GPGME_SIGSUM_KEY_EXPIRED: gpgme_sigsum_t = 0x0020;
pub const GPGME_SIGSUM_SIG_EXPIRED: gpgme_sigsum_t = 0x0040;
pub const GPGME_SIGSUM_KEY_MISSING: gpgme_sigsum_t = 0x0080;
pub const GPGME_SIGSUM_CRL_MISSING: gpgme_sigsum_t = 0x0100;
pub const GPGME_SIGSUM_CRL_TOO_OLD: gpgme_sigsum_t = 0x0200;
pub const GPGME_SIGSUM_BAD_POLICY: gpgme_sigsum_t = 0x0400;
pub const GPGME_SIGSUM_SYS_ERROR: gpgme_sigsum_t = 0x0800;

pub const GPGME_IMPORT_NEW: c_uint = 1;
pub const GPGME_IMPORT_UID: c_uint = 2;
pub const GPGME_IMPORT_SIG: c_uint = 4;
pub const GPGME_IMPORT_SUBKEY: c_uint = 8;
pub const GPGME_IMPORT_SECRET: c_uint = 16;

enum_from_primitive! {
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub enum gpgme_conf_level_t {
        GPGME_CONF_BASIC = 0,
        GPGME_CONF_ADVANCED = 1,
        GPGME_CONF_EXPERT = 2,
        GPGME_CONF_INVISIBLE = 3,
        GPGME_CONF_INTERNAL = 4
    }
}
pub use self::gpgme_conf_level_t::*;

enum_from_primitive! {
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub enum gpgme_conf_type_t {
        GPGME_CONF_NONE = 0,
        GPGME_CONF_STRING = 1,
        GPGME_CONF_INT32 = 2,
        GPGME_CONF_UINT32 = 3,

        GPGME_CONF_FILENAME = 32,
        GPGME_CONF_LDAP_SERVER = 33,
        GPGME_CONF_KEY_FPR = 34,
        GPGME_CONF_PUB_KEY = 35,
        GPGME_CONF_SEC_KEY = 36,
        GPGME_CONF_ALIAS_LIST = 37
    }
}
pub use self::gpgme_conf_type_t::*;

pub const GPGME_CONF_GROUP: isize = (1 << 0);
pub const GPGME_CONF_OPTIONAL: isize = (1 << 1);
pub const GPGME_CONF_LIST: isize = (1 << 2);
pub const GPGME_CONF_RUNTIME: isize = (1 << 3);
pub const GPGME_CONF_DEFAULT: isize = (1 << 4);
pub const GPGME_CONF_DEFAULT_DESC: isize = (1 << 5);
pub const GPGME_CONF_NO_ARG_DESC: isize = (1 << 6);
pub const GPGME_CONF_NO_CHANGE: isize = (1 << 7);
