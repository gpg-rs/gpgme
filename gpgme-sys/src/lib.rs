// Updated for GPGME 1.23
use libc::*;

pub use libgpg_error_sys::{
    consts::*, gpg_err_code as gpgme_err_code,
    gpg_err_code_from_errno as gpgme_err_code_from_errno,
    gpg_err_code_from_syserror as gpgme_err_code_from_syserror, gpg_err_code_t as gpgme_err_code_t,
    gpg_err_code_to_errno as gpgme_err_code_to_errno, gpg_err_make as gpgme_err_make,
    gpg_err_make_from_errno as gpgme_err_make_from_errno, gpg_err_set_errno as gpgme_err_set_errno,
    gpg_err_source as gpgme_err_source, gpg_err_source_t as gpgme_err_source_t,
    gpg_error_from_errno as gpgme_error_from_errno,
    gpg_error_from_syserror as gpgme_error_from_syserror, gpg_error_t as gpgme_error_t,
    gpg_strerror as gpgme_strerror, gpg_strerror_r as gpgme_strerror_r,
    gpg_strsource as gpgme_strsource,
};

pub type gpgme_data_encoding_t = c_uint;
pub const GPGME_DATA_ENCODING_NONE: gpgme_data_encoding_t = 0;
pub const GPGME_DATA_ENCODING_BINARY: gpgme_data_encoding_t = 1;
pub const GPGME_DATA_ENCODING_BASE64: gpgme_data_encoding_t = 2;
pub const GPGME_DATA_ENCODING_ARMOR: gpgme_data_encoding_t = 3;
pub const GPGME_DATA_ENCODING_URL: gpgme_data_encoding_t = 4;
pub const GPGME_DATA_ENCODING_URLESC: gpgme_data_encoding_t = 5;
pub const GPGME_DATA_ENCODING_URL0: gpgme_data_encoding_t = 6;
pub const GPGME_DATA_ENCODING_MIME: gpgme_data_encoding_t = 7;

pub type gpgme_data_type_t = c_uint;
pub const GPGME_DATA_TYPE_INVALID: gpgme_data_type_t = 0;
pub const GPGME_DATA_TYPE_UNKNOWN: gpgme_data_type_t = 1;
pub const GPGME_DATA_TYPE_PGP_SIGNED: gpgme_data_type_t = 0x10;
pub const GPGME_DATA_TYPE_PGP_ENCRYPTED: gpgme_data_type_t = 0x11;
pub const GPGME_DATA_TYPE_PGP_OTHER: gpgme_data_type_t = 0x12;
pub const GPGME_DATA_TYPE_PGP_KEY: gpgme_data_type_t = 0x13;
pub const GPGME_DATA_TYPE_PGP_SIGNATURE: gpgme_data_type_t = 0x18;
pub const GPGME_DATA_TYPE_CMS_SIGNED: gpgme_data_type_t = 0x20;
pub const GPGME_DATA_TYPE_CMS_ENCRYPTED: gpgme_data_type_t = 0x21;
pub const GPGME_DATA_TYPE_CMS_OTHER: gpgme_data_type_t = 0x22;
pub const GPGME_DATA_TYPE_X509_CERT: gpgme_data_type_t = 0x23;
pub const GPGME_DATA_TYPE_PKCS12: gpgme_data_type_t = 0x24;

pub type gpgme_pubkey_algo_t = c_uint;
pub const GPGME_PK_RSA: gpgme_pubkey_algo_t = 1;
pub const GPGME_PK_RSA_E: gpgme_pubkey_algo_t = 2;
pub const GPGME_PK_RSA_S: gpgme_pubkey_algo_t = 3;
pub const GPGME_PK_ELG_E: gpgme_pubkey_algo_t = 16;
pub const GPGME_PK_DSA: gpgme_pubkey_algo_t = 17;
pub const GPGME_PK_ECC: gpgme_pubkey_algo_t = 18;
pub const GPGME_PK_ELG: gpgme_pubkey_algo_t = 20;
pub const GPGME_PK_ECDSA: gpgme_pubkey_algo_t = 301;
pub const GPGME_PK_ECDH: gpgme_pubkey_algo_t = 302;
pub const GPGME_PK_EDDSA: gpgme_pubkey_algo_t = 303;

pub type gpgme_hash_algo_t = c_uint;
pub const GPGME_MD_NONE: gpgme_hash_algo_t = 0;
pub const GPGME_MD_MD5: gpgme_hash_algo_t = 1;
pub const GPGME_MD_SHA1: gpgme_hash_algo_t = 2;
pub const GPGME_MD_RMD160: gpgme_hash_algo_t = 3;
pub const GPGME_MD_MD2: gpgme_hash_algo_t = 5;
pub const GPGME_MD_TIGER: gpgme_hash_algo_t = 6;
pub const GPGME_MD_HAVAL: gpgme_hash_algo_t = 7;
pub const GPGME_MD_SHA256: gpgme_hash_algo_t = 8;
pub const GPGME_MD_SHA384: gpgme_hash_algo_t = 9;
pub const GPGME_MD_SHA512: gpgme_hash_algo_t = 10;
pub const GPGME_MD_SHA224: gpgme_hash_algo_t = 11;
pub const GPGME_MD_MD4: gpgme_hash_algo_t = 301;
pub const GPGME_MD_CRC32: gpgme_hash_algo_t = 302;
pub const GPGME_MD_CRC32_RFC1510: gpgme_hash_algo_t = 303;
pub const GPGME_MD_CRC24_RFC2440: gpgme_hash_algo_t = 304;

pub type gpgme_sig_mode_t = c_uint;
pub const GPGME_SIG_MODE_NORMAL: gpgme_sig_mode_t = 0;
pub const GPGME_SIG_MODE_DETACH: gpgme_sig_mode_t = 1;
pub const GPGME_SIG_MODE_CLEAR: gpgme_sig_mode_t = 2;
// 1.19
pub const GPGME_SIG_MODE_ARCHIVE: gpgme_sig_mode_t = 4;

pub type gpgme_validity_t = c_uint;
pub const GPGME_VALIDITY_UNKNOWN: gpgme_validity_t = 0;
pub const GPGME_VALIDITY_UNDEFINED: gpgme_validity_t = 1;
pub const GPGME_VALIDITY_NEVER: gpgme_validity_t = 2;
pub const GPGME_VALIDITY_MARGINAL: gpgme_validity_t = 3;
pub const GPGME_VALIDITY_FULL: gpgme_validity_t = 4;
pub const GPGME_VALIDITY_ULTIMATE: gpgme_validity_t = 5;

pub type gpgme_tofu_policy_t = c_uint;
pub const GPGME_TOFU_POLICY_NONE: gpgme_tofu_policy_t = 0;
pub const GPGME_TOFU_POLICY_AUTO: gpgme_tofu_policy_t = 1;
pub const GPGME_TOFU_POLICY_GOOD: gpgme_tofu_policy_t = 2;
pub const GPGME_TOFU_POLICY_UNKNOWN: gpgme_tofu_policy_t = 3;
pub const GPGME_TOFU_POLICY_BAD: gpgme_tofu_policy_t = 4;
pub const GPGME_TOFU_POLICY_ASK: gpgme_tofu_policy_t = 5;

pub type gpgme_keyorg_t = c_uint;
pub const GPGME_KEYORG_UNKNOWN: gpgme_keyorg_t = 0;
pub const GPGME_KEYORG_KS: gpgme_keyorg_t = 1;
pub const GPGME_KEYORG_DANE: gpgme_keyorg_t = 3;
pub const GPGME_KEYORG_WKD: gpgme_keyorg_t = 4;
pub const GPGME_KEYORG_URL: gpgme_keyorg_t = 5;
pub const GPGME_KEYORG_FILE: gpgme_keyorg_t = 6;
pub const GPGME_KEYORG_SELF: gpgme_keyorg_t = 7;
pub const GPGME_KEYORG_OTHER: gpgme_keyorg_t = 31;

pub type gpgme_protocol_t = c_uint;
pub const GPGME_PROTOCOL_OpenPGP: gpgme_protocol_t = 0;
pub const GPGME_PROTOCOL_CMS: gpgme_protocol_t = 1;
pub const GPGME_PROTOCOL_GPGCONF: gpgme_protocol_t = 2;
pub const GPGME_PROTOCOL_ASSUAN: gpgme_protocol_t = 3;
pub const GPGME_PROTOCOL_G13: gpgme_protocol_t = 4;
pub const GPGME_PROTOCOL_UISERVER: gpgme_protocol_t = 5;
pub const GPGME_PROTOCOL_SPAWN: gpgme_protocol_t = 6;
pub const GPGME_PROTOCOL_DEFAULT: gpgme_protocol_t = 254;
pub const GPGME_PROTOCOL_UNKNOWN: gpgme_protocol_t = 255;

pub type gpgme_keylist_mode_t = c_uint;
pub const GPGME_KEYLIST_MODE_LOCAL: gpgme_keylist_mode_t = 1;
pub const GPGME_KEYLIST_MODE_EXTERN: gpgme_keylist_mode_t = 2;
pub const GPGME_KEYLIST_MODE_SIGS: gpgme_keylist_mode_t = 4;
pub const GPGME_KEYLIST_MODE_SIG_NOTATIONS: gpgme_keylist_mode_t = 8;
pub const GPGME_KEYLIST_MODE_WITH_SECRET: gpgme_keylist_mode_t = 16;
pub const GPGME_KEYLIST_MODE_WITH_TOFU: gpgme_keylist_mode_t = 32;
// 1.14
pub const GPGME_KEYLIST_MODE_WITH_KEYGRIP: gpgme_keylist_mode_t = 64;
pub const GPGME_KEYLIST_MODE_EPHEMERAL: gpgme_keylist_mode_t = 128;
pub const GPGME_KEYLIST_MODE_VALIDATE: gpgme_keylist_mode_t = 256;
// 1.18
pub const GPGME_KEYLIST_MODE_FORCE_EXTERN: gpgme_keylist_mode_t = 512;
// 1.23
pub const GPGME_KEYLIST_MODE_WITH_V5FPR: gpgme_keylist_mode_t = 1024;

pub const GPGME_KEYLIST_MODE_LOCATE: gpgme_keylist_mode_t =
    GPGME_KEYLIST_MODE_LOCAL | GPGME_KEYLIST_MODE_EXTERN;
// 1.18
pub const GPGME_KEYLIST_MODE_LOCATE_EXTERNAL: gpgme_keylist_mode_t =
    GPGME_KEYLIST_MODE_LOCATE | GPGME_KEYLIST_MODE_FORCE_EXTERN;

pub type gpgme_pinentry_mode_t = c_uint;
pub const GPGME_PINENTRY_MODE_DEFAULT: gpgme_pinentry_mode_t = 0;
pub const GPGME_PINENTRY_MODE_ASK: gpgme_pinentry_mode_t = 1;
pub const GPGME_PINENTRY_MODE_CANCEL: gpgme_pinentry_mode_t = 2;
pub const GPGME_PINENTRY_MODE_ERROR: gpgme_pinentry_mode_t = 3;
pub const GPGME_PINENTRY_MODE_LOOPBACK: gpgme_pinentry_mode_t = 4;

pub type gpgme_export_mode_t = c_uint;
pub const GPGME_EXPORT_MODE_EXTERN: gpgme_export_mode_t = 2;
pub const GPGME_EXPORT_MODE_MINIMAL: gpgme_export_mode_t = 4;
pub const GPGME_EXPORT_MODE_SECRET: gpgme_export_mode_t = 16;
pub const GPGME_EXPORT_MODE_RAW: gpgme_export_mode_t = 32;
pub const GPGME_EXPORT_MODE_PKCS12: gpgme_export_mode_t = 64;
// 1.14
pub const GPGME_EXPORT_MODE_SSH: gpgme_export_mode_t = 256;
// 1.17
pub const GPGME_EXPORT_MODE_SECRET_SUBKEY: gpgme_export_mode_t = 512;

pub const GPGME_AUDITLOG_DEFAULT: c_uint = 0;
pub const GPGME_AUDITLOG_HTML: c_uint = 1;
pub const GPGME_AUDITLOG_DIAG: c_uint = 2;
pub const GPGME_AUDITLOG_WITH_HELP: c_uint = 128;

pub type gpgme_sig_notation_flags_t = c_uint;
pub const GPGME_SIG_NOTATION_HUMAN_READABLE: gpgme_sig_notation_flags_t = 1;
pub const GPGME_SIG_NOTATION_CRITICAL: gpgme_sig_notation_flags_t = 2;

pub type gpgme_status_code_t = c_uint;
pub const GPGME_STATUS_EOF: gpgme_status_code_t = 0;

pub const GPGME_STATUS_ENTER: gpgme_status_code_t = 1;
pub const GPGME_STATUS_LEAVE: gpgme_status_code_t = 2;
pub const GPGME_STATUS_ABORT: gpgme_status_code_t = 3;

pub const GPGME_STATUS_GOODSIG: gpgme_status_code_t = 4;
pub const GPGME_STATUS_BADSIG: gpgme_status_code_t = 5;
pub const GPGME_STATUS_ERRSIG: gpgme_status_code_t = 6;

pub const GPGME_STATUS_BADARMOR: gpgme_status_code_t = 7;

pub const GPGME_STATUS_RSA_OR_IDEA: gpgme_status_code_t = 8;
pub const GPGME_STATUS_KEYEXPIRED: gpgme_status_code_t = 9;
pub const GPGME_STATUS_KEYREVOKED: gpgme_status_code_t = 10;

pub const GPGME_STATUS_TRUST_UNDEFINED: gpgme_status_code_t = 11;
pub const GPGME_STATUS_TRUST_NEVER: gpgme_status_code_t = 12;
pub const GPGME_STATUS_TRUST_MARGINAL: gpgme_status_code_t = 13;
pub const GPGME_STATUS_TRUST_FULLY: gpgme_status_code_t = 14;
pub const GPGME_STATUS_TRUST_ULTIMATE: gpgme_status_code_t = 15;

pub const GPGME_STATUS_SHM_INFO: gpgme_status_code_t = 16;
pub const GPGME_STATUS_SHM_GET: gpgme_status_code_t = 17;
pub const GPGME_STATUS_SHM_GET_BOOL: gpgme_status_code_t = 18;
pub const GPGME_STATUS_SHM_GET_HIDDEN: gpgme_status_code_t = 19;

pub const GPGME_STATUS_NEED_PASSPHRASE: gpgme_status_code_t = 20;
pub const GPGME_STATUS_VALIDSIG: gpgme_status_code_t = 21;
pub const GPGME_STATUS_SIG_ID: gpgme_status_code_t = 22;
pub const GPGME_STATUS_ENC_TO: gpgme_status_code_t = 23;
pub const GPGME_STATUS_NODATA: gpgme_status_code_t = 24;
pub const GPGME_STATUS_BAD_PASSPHRASE: gpgme_status_code_t = 25;
pub const GPGME_STATUS_NO_PUBKEY: gpgme_status_code_t = 26;
pub const GPGME_STATUS_NO_SECKEY: gpgme_status_code_t = 27;
pub const GPGME_STATUS_NEED_PASSPHRASE_SYM: gpgme_status_code_t = 28;
pub const GPGME_STATUS_DECRYPTION_FAILED: gpgme_status_code_t = 29;
pub const GPGME_STATUS_DECRYPTION_OKAY: gpgme_status_code_t = 30;
pub const GPGME_STATUS_MISSING_PASSPHRASE: gpgme_status_code_t = 31;
pub const GPGME_STATUS_GOOD_PASSPHRASE: gpgme_status_code_t = 32;
pub const GPGME_STATUS_GOODMDC: gpgme_status_code_t = 33;
pub const GPGME_STATUS_BADMDC: gpgme_status_code_t = 34;
pub const GPGME_STATUS_ERRMDC: gpgme_status_code_t = 35;
pub const GPGME_STATUS_IMPORTED: gpgme_status_code_t = 36;
pub const GPGME_STATUS_IMPORT_OK: gpgme_status_code_t = 37;
pub const GPGME_STATUS_IMPORT_PROBLEM: gpgme_status_code_t = 38;
pub const GPGME_STATUS_IMPORT_RES: gpgme_status_code_t = 39;
pub const GPGME_STATUS_FILE_START: gpgme_status_code_t = 40;
pub const GPGME_STATUS_FILE_DONE: gpgme_status_code_t = 41;
pub const GPGME_STATUS_FILE_ERROR: gpgme_status_code_t = 42;

pub const GPGME_STATUS_BEGIN_DECRYPTION: gpgme_status_code_t = 43;
pub const GPGME_STATUS_END_DECRYPTION: gpgme_status_code_t = 44;
pub const GPGME_STATUS_BEGIN_ENCRYPTION: gpgme_status_code_t = 45;
pub const GPGME_STATUS_END_ENCRYPTION: gpgme_status_code_t = 46;

pub const GPGME_STATUS_DELETE_PROBLEM: gpgme_status_code_t = 47;
pub const GPGME_STATUS_GET_BOOL: gpgme_status_code_t = 48;
pub const GPGME_STATUS_GET_LINE: gpgme_status_code_t = 49;
pub const GPGME_STATUS_GET_HIDDEN: gpgme_status_code_t = 50;
pub const GPGME_STATUS_GOT_IT: gpgme_status_code_t = 51;
pub const GPGME_STATUS_PROGRESS: gpgme_status_code_t = 52;
pub const GPGME_STATUS_SIG_CREATED: gpgme_status_code_t = 53;
pub const GPGME_STATUS_SESSION_KEY: gpgme_status_code_t = 54;
pub const GPGME_STATUS_NOTATION_NAME: gpgme_status_code_t = 55;
pub const GPGME_STATUS_NOTATION_DATA: gpgme_status_code_t = 56;
pub const GPGME_STATUS_POLICY_URL: gpgme_status_code_t = 57;
pub const GPGME_STATUS_BEGIN_STREAM: gpgme_status_code_t = 58;
pub const GPGME_STATUS_END_STREAM: gpgme_status_code_t = 59;
pub const GPGME_STATUS_KEY_CREATED: gpgme_status_code_t = 60;
pub const GPGME_STATUS_USERID_HINT: gpgme_status_code_t = 61;
pub const GPGME_STATUS_UNEXPECTED: gpgme_status_code_t = 62;
pub const GPGME_STATUS_INV_RECP: gpgme_status_code_t = 63;
pub const GPGME_STATUS_NO_RECP: gpgme_status_code_t = 64;
pub const GPGME_STATUS_ALREADY_SIGNED: gpgme_status_code_t = 65;
pub const GPGME_STATUS_SIGEXPIRED: gpgme_status_code_t = 66;
pub const GPGME_STATUS_EXPSIG: gpgme_status_code_t = 67;
pub const GPGME_STATUS_EXPKEYSIG: gpgme_status_code_t = 68;
pub const GPGME_STATUS_TRUNCATED: gpgme_status_code_t = 69;
pub const GPGME_STATUS_ERROR: gpgme_status_code_t = 70;
pub const GPGME_STATUS_NEWSIG: gpgme_status_code_t = 71;
pub const GPGME_STATUS_REVKEYSIG: gpgme_status_code_t = 72;
pub const GPGME_STATUS_SIG_SUBPACKET: gpgme_status_code_t = 73;
pub const GPGME_STATUS_NEED_PASSPHRASE_PIN: gpgme_status_code_t = 74;
pub const GPGME_STATUS_SC_OP_FAILURE: gpgme_status_code_t = 75;
pub const GPGME_STATUS_SC_OP_SUCCESS: gpgme_status_code_t = 76;
pub const GPGME_STATUS_CARDCTRL: gpgme_status_code_t = 77;
pub const GPGME_STATUS_BACKUP_KEY_CREATED: gpgme_status_code_t = 78;
pub const GPGME_STATUS_PKA_TRUST_BAD: gpgme_status_code_t = 79;
pub const GPGME_STATUS_PKA_TRUST_GOOD: gpgme_status_code_t = 80;
pub const GPGME_STATUS_PLAINTEXT: gpgme_status_code_t = 81;
pub const GPGME_STATUS_INV_SGNR: gpgme_status_code_t = 82;
pub const GPGME_STATUS_NO_SGNR: gpgme_status_code_t = 83;
pub const GPGME_STATUS_SUCCESS: gpgme_status_code_t = 84;
pub const GPGME_STATUS_DECRYPTION_INFO: gpgme_status_code_t = 85;
pub const GPGME_STATUS_PLAINTEXT_LENGTH: gpgme_status_code_t = 86;
pub const GPGME_STATUS_MOUNTPOINT: gpgme_status_code_t = 87;
pub const GPGME_STATUS_PINENTRY_LAUNCHED: gpgme_status_code_t = 88;
pub const GPGME_STATUS_ATTRIBUTE: gpgme_status_code_t = 89;
pub const GPGME_STATUS_BEGIN_SIGNING: gpgme_status_code_t = 90;
pub const GPGME_STATUS_KEY_NOT_CREATED: gpgme_status_code_t = 91;
pub const GPGME_STATUS_INQUIRE_MAXLEN: gpgme_status_code_t = 92;
pub const GPGME_STATUS_FAILURE: gpgme_status_code_t = 93;
pub const GPGME_STATUS_KEY_CONSIDERED: gpgme_status_code_t = 94;
pub const GPGME_STATUS_TOFU_USER: gpgme_status_code_t = 95;
pub const GPGME_STATUS_TOFU_STATS: gpgme_status_code_t = 96;
pub const GPGME_STATUS_TOFU_STATS_LONG: gpgme_status_code_t = 97;
pub const GPGME_STATUS_NOTATION_FLAGS: gpgme_status_code_t = 98;

pub const GPGME_INCLUDE_CERTS_DEFAULT: c_int = -256;

pub type gpgme_event_io_t = c_uint;
pub const GPGME_EVENT_START: gpgme_event_io_t = 0;
pub const GPGME_EVENT_DONE: gpgme_event_io_t = 1;
pub const GPGME_EVENT_NEXT_KEY: gpgme_event_io_t = 2;

pub type gpgme_encrypt_flags_t = c_uint;
pub const GPGME_ENCRYPT_ALWAYS_TRUST: gpgme_encrypt_flags_t = 1;
pub const GPGME_ENCRYPT_NO_ENCRYPT_TO: gpgme_encrypt_flags_t = 2;
pub const GPGME_ENCRYPT_PREPARE: gpgme_encrypt_flags_t = 4;
pub const GPGME_ENCRYPT_EXPECT_SIGN: gpgme_encrypt_flags_t = 8;
pub const GPGME_ENCRYPT_NO_COMPRESS: gpgme_encrypt_flags_t = 16;
pub const GPGME_ENCRYPT_SYMMETRIC: gpgme_encrypt_flags_t = 32;
pub const GPGME_ENCRYPT_THROW_KEYIDS: gpgme_encrypt_flags_t = 64;
pub const GPGME_ENCRYPT_WRAP: gpgme_encrypt_flags_t = 128;
pub const GPGME_ENCRYPT_WANT_ADDRESS: gpgme_encrypt_flags_t = 256;
// 1.19
pub const GPGME_ENCRYPT_ARCHIVE: gpgme_encrypt_flags_t = 512;

pub type gpgme_decrypt_flags_t = c_uint;
pub const GPGME_DECRYPT_VERIFY: gpgme_decrypt_flags_t = 1;
// 1.19
pub const GPGME_DECRYPT_ARCHIVE: gpgme_decrypt_flags_t = 2;
pub const GPGME_DECRYPT_UNWRAP: gpgme_decrypt_flags_t = 128;

// 1.19
pub type gpgme_verify_flags_t = c_uint;
pub const GPGME_VERIFY_ARCHIVE: gpgme_verify_flags_t = 1;

pub type gpgme_sigsum_t = c_uint;
pub const GPGME_SIGSUM_VALID: gpgme_sigsum_t = 0x0001;
pub const GPGME_SIGSUM_GREEN: gpgme_sigsum_t = 0x0002;
pub const GPGME_SIGSUM_RED: gpgme_sigsum_t = 0x0004;
pub const GPGME_SIGSUM_KEY_REVOKED: gpgme_sigsum_t = 0x0010;
pub const GPGME_SIGSUM_KEY_EXPIRED: gpgme_sigsum_t = 0x0020;
pub const GPGME_SIGSUM_SIG_EXPIRED: gpgme_sigsum_t = 0x0040;
pub const GPGME_SIGSUM_KEY_MISSING: gpgme_sigsum_t = 0x0080;
pub const GPGME_SIGSUM_CRL_MISSING: gpgme_sigsum_t = 0x0100;
pub const GPGME_SIGSUM_CRL_TOO_OLD: gpgme_sigsum_t = 0x0200;
pub const GPGME_SIGSUM_BAD_POLICY: gpgme_sigsum_t = 0x0400;
pub const GPGME_SIGSUM_SYS_ERROR: gpgme_sigsum_t = 0x0800;
pub const GPGME_SIGSUM_TOFU_CONFLICT: gpgme_sigsum_t = 0x1000;

pub const GPGME_IMPORT_NEW: c_uint = 1;
pub const GPGME_IMPORT_UID: c_uint = 2;
pub const GPGME_IMPORT_SIG: c_uint = 4;
pub const GPGME_IMPORT_SUBKEY: c_uint = 8;
pub const GPGME_IMPORT_SECRET: c_uint = 16;

pub const GPGME_CREATE_SIGN: c_uint = 1 << 0;
pub const GPGME_CREATE_ENCR: c_uint = 1 << 1;
pub const GPGME_CREATE_CERT: c_uint = 1 << 2;
pub const GPGME_CREATE_AUTH: c_uint = 1 << 3;
pub const GPGME_CREATE_NOPASSWD: c_uint = 1 << 7;
pub const GPGME_CREATE_SELFSIGNED: c_uint = 1 << 8;
pub const GPGME_CREATE_NOSTORE: c_uint = 1 << 9;
pub const GPGME_CREATE_WANTPUB: c_uint = 1 << 10;
pub const GPGME_CREATE_WANTSEC: c_uint = 1 << 11;
pub const GPGME_CREATE_FORCE: c_uint = 1 << 12;
pub const GPGME_CREATE_NOEXPIRE: c_uint = 1 << 13;

pub const GPGME_KEYSIGN_LOCAL: c_uint = 1 << 7;
pub const GPGME_KEYSIGN_LFSEP: c_uint = 1 << 8;
pub const GPGME_KEYSIGN_NOEXPIRE: c_uint = 1 << 9;
// 1.16
pub const GPGME_KEYSIGN_FORCE: c_uint = 1 << 10;

// 1.15
pub const GPGME_REVSIG_LFSEP: c_uint = 1 << 8;

pub const GPGME_INTERACT_CARD: c_uint = 1 << 0;

pub const GPGME_SPAWN_DETACHED: c_uint = 1;
pub const GPGME_SPAWN_ALLOW_SET_FG: c_uint = 2;

pub const GPGME_DELETE_ALLOW_SECRET: c_uint = 1 << 0;
pub const GPGME_DELETE_FORCE: c_uint = 1 << 1;

pub type gpgme_conf_level_t = c_uint;
pub const GPGME_CONF_BASIC: gpgme_conf_level_t = 0;
pub const GPGME_CONF_ADVANCED: gpgme_conf_level_t = 1;
pub const GPGME_CONF_EXPERT: gpgme_conf_level_t = 2;
pub const GPGME_CONF_INVISIBLE: gpgme_conf_level_t = 3;
pub const GPGME_CONF_INTERNAL: gpgme_conf_level_t = 4;

pub type gpgme_conf_type_t = c_uint;
pub const GPGME_CONF_NONE: gpgme_conf_type_t = 0;
pub const GPGME_CONF_STRING: gpgme_conf_type_t = 1;
pub const GPGME_CONF_INT32: gpgme_conf_type_t = 2;
pub const GPGME_CONF_UINT32: gpgme_conf_type_t = 3;

pub const GPGME_CONF_FILENAME: gpgme_conf_type_t = 32;
pub const GPGME_CONF_LDAP_SERVER: gpgme_conf_type_t = 33;
pub const GPGME_CONF_KEY_FPR: gpgme_conf_type_t = 34;
pub const GPGME_CONF_PUB_KEY: gpgme_conf_type_t = 35;
pub const GPGME_CONF_SEC_KEY: gpgme_conf_type_t = 36;
pub const GPGME_CONF_ALIAS_LIST: gpgme_conf_type_t = 37;

pub const GPGME_CONF_GROUP: gpgme_conf_type_t = 1 << 0;
pub const GPGME_CONF_OPTIONAL: gpgme_conf_type_t = 1 << 1;
pub const GPGME_CONF_LIST: gpgme_conf_type_t = 1 << 2;
pub const GPGME_CONF_RUNTIME: gpgme_conf_type_t = 1 << 3;
pub const GPGME_CONF_DEFAULT: gpgme_conf_type_t = 1 << 4;
pub const GPGME_CONF_DEFAULT_DESC: gpgme_conf_type_t = 1 << 5;
pub const GPGME_CONF_NO_ARG_DESC: gpgme_conf_type_t = 1 << 6;
pub const GPGME_CONF_NO_CHANGE: gpgme_conf_type_t = 1 << 7;

#[cfg(all(target_os = "windows", target_arch = "x86"))]
pub type gpgme_off_t = i32;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub type gpgme_off_t = i64;
#[cfg(not(target_os = "windows"))]
pub type gpgme_off_t = off_t;

pub type gpgme_ssize_t = ssize_t;

// extern {
//     pub type gpgme_context;
//     pub type gpgme_data;
// }
#[repr(C)]
pub struct gpgme_context {
    _priv: [u8; 0],
}

#[repr(C)]
pub struct gpgme_data {
    _priv: [u8; 0],
}

pub type gpgme_ctx_t = *mut gpgme_context;
pub type gpgme_data_t = *mut gpgme_data;

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_sig_notation {
    pub next: gpgme_sig_notation_t,
    pub name: *mut c_char,
    pub value: *mut c_char,
    pub name_len: c_int,
    pub value_len: c_int,
    pub flags: gpgme_sig_notation_flags_t,
    pub bitfield: u32,
}
pub type gpgme_sig_notation_t = *mut _gpgme_sig_notation;

impl _gpgme_sig_notation {
    #[inline]
    pub fn human_readable(&self) -> bool {
        (self.bitfield & 0b01) == 0b01
    }

    #[inline]
    pub fn critical(&self) -> bool {
        (self.bitfield & 0b10) == 0b10
    }
}

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_engine_info {
    pub next: gpgme_engine_info_t,
    pub protocol: gpgme_protocol_t,
    pub file_name: *mut c_char,
    pub version: *mut c_char,
    pub req_version: *const c_char,
    pub home_dir: *mut c_char,
}
pub type gpgme_engine_info_t = *mut _gpgme_engine_info;

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_tofu_info {
    pub next: gpgme_tofu_info_t,
    pub bitfield: u32,
    pub signcount: c_ushort,
    pub encrcount: c_ushort,
    pub signfirst: c_ulong,
    pub signlast: c_ulong,
    pub encrfirst: c_ulong,
    pub encrlast: c_ulong,
    pub description: *mut c_char,
}
pub type gpgme_tofu_info_t = *mut _gpgme_tofu_info;

impl _gpgme_tofu_info {
    #[inline]
    pub fn validity(&self) -> c_uint {
        (self.bitfield & 0b0000_0111) as c_uint
    }

    #[inline]
    pub fn policy(&self) -> gpgme_tofu_policy_t {
        ((self.bitfield & 0b1111_0000) >> 4) as gpgme_tofu_policy_t
    }
}

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_subkey {
    pub next: gpgme_subkey_t,
    pub bitfield: u32,
    pub pubkey_algo: gpgme_pubkey_algo_t,
    pub length: c_uint,
    pub keyid: *mut c_char,
    _keyid: [c_char; 17],
    pub fpr: *mut c_char,
    pub timestamp: c_long,
    pub expires: c_long,
    pub card_number: *mut c_char,
    pub curve: *mut c_char,
    pub keygrip: *mut c_char,
}
pub type gpgme_subkey_t = *mut _gpgme_subkey;

impl _gpgme_subkey {
    #[inline]
    pub fn revoked(&self) -> bool {
        (self.bitfield & 0x1) == 0x1
    }
    #[inline]
    pub fn expired(&self) -> bool {
        (self.bitfield & 0x2) == 0x2
    }
    #[inline]
    pub fn disabled(&self) -> bool {
        (self.bitfield & 0x4) == 0x4
    }
    #[inline]
    pub fn invalid(&self) -> bool {
        (self.bitfield & 0x8) == 0x8
    }
    #[inline]
    pub fn can_encrypt(&self) -> bool {
        (self.bitfield & 0x10) == 0x10
    }
    #[inline]
    pub fn can_sign(&self) -> bool {
        (self.bitfield & 0x20) == 0x20
    }
    #[inline]
    pub fn can_certify(&self) -> bool {
        (self.bitfield & 0x40) == 0x40
    }
    #[inline]
    pub fn secret(&self) -> bool {
        (self.bitfield & 0x80) == 0x80
    }
    #[inline]
    pub fn can_authenticate(&self) -> bool {
        (self.bitfield & 0x100) == 0x100
    }
    #[inline]
    pub fn is_qualified(&self) -> bool {
        (self.bitfield & 0x200) == 0x200
    }
    #[inline]
    pub fn is_cardkey(&self) -> bool {
        (self.bitfield & 0x400) == 0x400
    }
    #[inline]
    pub fn is_de_vs(&self) -> bool {
        (self.bitfield & 0x800) == 0x800
    }
    // 1.20
    #[inline]
    pub fn can_renc(&self) -> bool {
        (self.bitfield & 0x1000) == 0x1000
    }
    // 1.20
    #[inline]
    pub fn can_timestamp(&self) -> bool {
        (self.bitfield & 0x2000) == 0x2000
    }
    // 1.20
    #[inline]
    pub fn is_group_owned(&self) -> bool {
        (self.bitfield & 0x4000) == 0x4000
    }
}

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_key_sig {
    pub next: gpgme_key_sig_t,
    pub bitfield: u32,
    pub pubkey_algo: gpgme_pubkey_algo_t,
    pub keyid: *mut c_char,
    _keyid: [c_char; 17],
    pub timestamp: c_long,
    pub expires: c_long,
    pub status: gpgme_error_t,
    _class: c_uint,
    pub uid: *mut c_char,
    pub name: *mut c_char,
    pub email: *mut c_char,
    pub comment: *mut c_char,
    pub sig_class: c_uint,
    pub notations: gpgme_sig_notation_t,
    _last_notation: gpgme_sig_notation_t,
    // 1.16
    pub trust_scope: *mut c_char,
}
pub type gpgme_key_sig_t = *mut _gpgme_key_sig;

impl _gpgme_key_sig {
    #[inline]
    pub fn revoked(&self) -> bool {
        (self.bitfield & 0b0001) == 0b0001
    }
    #[inline]
    pub fn expired(&self) -> bool {
        (self.bitfield & 0b0010) == 0b0010
    }
    #[inline]
    pub fn invalid(&self) -> bool {
        (self.bitfield & 0b0100) == 0b0100
    }
    #[inline]
    pub fn exportable(&self) -> bool {
        (self.bitfield & 0b1000) == 0b1000
    }
    // 1.16
    #[inline]
    pub fn trust_depth(&self) -> u8 {
        ((self.bitfield >> 16) & 0xFF) as u8
    }
    // 1.16
    #[inline]
    pub fn trust_value(&self) -> u8 {
        (self.bitfield >> 24) as u8
    }
}

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_user_id {
    pub next: gpgme_user_id_t,
    pub bitfield: u32,
    pub validity: gpgme_validity_t,
    pub uid: *mut c_char,
    pub name: *mut c_char,
    pub email: *mut c_char,
    pub comment: *mut c_char,
    pub signatures: gpgme_key_sig_t,
    _last_keysig: gpgme_key_sig_t,
    pub address: *mut c_char,
    pub tofu: gpgme_tofu_info_t,
    pub last_update: c_ulong,
    // 1.14
    pub uidhash: *mut c_char,
}
pub type gpgme_user_id_t = *mut _gpgme_user_id;

impl _gpgme_user_id {
    #[inline]
    pub fn revoked(&self) -> bool {
        (self.bitfield & 0b0001) == 0b0001
    }
    #[inline]
    pub fn invalid(&self) -> bool {
        (self.bitfield & 0b0010) == 0b0010
    }
    #[inline]
    pub fn origin(&self) -> u32 {
        self.bitfield >> 27
    }
}

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_key {
    _refs: c_uint,
    pub bitfield: u32,
    pub protocol: gpgme_protocol_t,
    pub issuer_serial: *mut c_char,
    pub issuer_name: *mut c_char,
    pub chain_id: *mut c_char,
    pub owner_trust: gpgme_validity_t,
    pub subkeys: gpgme_subkey_t,
    pub uids: gpgme_user_id_t,
    _last_subkey: gpgme_subkey_t,
    _last_uid: gpgme_user_id_t,
    pub keylist_mode: gpgme_keylist_mode_t,
    pub fpr: *mut c_char,
    pub last_update: c_ulong,
}
pub type gpgme_key_t = *mut _gpgme_key;

impl _gpgme_key {
    #[inline]
    pub fn revoked(&self) -> bool {
        (self.bitfield & 0x1) == 0x1
    }
    #[inline]
    pub fn expired(&self) -> bool {
        (self.bitfield & 0x2) == 0x2
    }
    #[inline]
    pub fn disabled(&self) -> bool {
        (self.bitfield & 0x4) == 0x4
    }
    #[inline]
    pub fn invalid(&self) -> bool {
        (self.bitfield & 0x8) == 0x8
    }
    #[inline]
    pub fn can_encrypt(&self) -> bool {
        (self.bitfield & 0x10) == 0x10
    }
    #[inline]
    pub fn can_sign(&self) -> bool {
        (self.bitfield & 0x20) == 0x20
    }
    #[inline]
    pub fn can_certify(&self) -> bool {
        (self.bitfield & 0x40) == 0x40
    }
    #[inline]
    pub fn secret(&self) -> bool {
        (self.bitfield & 0x80) == 0x80
    }
    #[inline]
    pub fn can_authenticate(&self) -> bool {
        (self.bitfield & 0x100) == 0x100
    }
    #[inline]
    pub fn is_qualified(&self) -> bool {
        (self.bitfield & 0x200) == 0x200
    }
    // 1.23
    #[inline]
    pub fn has_encrypt(&self) -> bool {
        (self.bitfield & 0x400) == 0x400
    }
    // 1.23
    #[inline]
    pub fn has_sign(&self) -> bool {
        (self.bitfield & 0x800) == 0x800
    }
    // 1.23
    #[inline]
    pub fn has_certify(&self) -> bool {
        (self.bitfield & 0x1000) == 0x1000
    }
    // 1.23
    #[inline]
    pub fn has_authenticate(&self) -> bool {
        (self.bitfield & 0x2000) == 0x2000
    }
    #[inline]
    pub fn origin(&self) -> u32 {
        self.bitfield >> 27
    }
}

pub type gpgme_passphrase_cb_t = Option<
    unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char, c_int, c_int) -> gpgme_error_t,
>;
pub type gpgme_progress_cb_t =
    Option<unsafe extern "C" fn(*mut c_void, *const c_char, c_int, c_int, c_int)>;
pub type gpgme_status_cb_t =
    Option<unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> gpgme_error_t>;
pub type gpgme_interact_cb_t =
    Option<unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char, c_int) -> gpgme_error_t>;
pub type gpgme_edit_cb_t = Option<
    unsafe extern "C" fn(*mut c_void, gpgme_status_code_t, *const c_char, c_int) -> gpgme_error_t,
>;

pub type gpgme_io_cb_t = Option<unsafe extern "C" fn(*mut c_void, c_int) -> gpgme_error_t>;
pub type gpgme_register_io_cb_t = Option<
    unsafe extern "C" fn(
        *mut c_void,
        c_int,
        c_int,
        gpgme_io_cb_t,
        *mut c_void,
        *mut *mut c_void,
    ) -> gpgme_error_t,
>;
pub type gpgme_remove_io_cb_t = Option<unsafe extern "C" fn(*mut c_void)>;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct gpgme_io_event_done_data {
    pub err: gpgme_error_t,
    pub op_err: gpgme_error_t,
}
pub type gpgme_io_event_done_data_t = *mut gpgme_io_event_done_data;

pub type gpgme_event_io_cb_t =
    Option<unsafe extern "C" fn(*mut c_void, gpgme_event_io_t, *mut c_void)>;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct gpgme_io_cbs {
    pub add: gpgme_register_io_cb_t,
    pub add_priv: *mut c_void,
    pub remove: gpgme_remove_io_cb_t,
    pub event: gpgme_event_io_cb_t,
    pub event_priv: *mut c_void,
}
pub type gpgme_io_cbs_t = *mut gpgme_io_cbs;

pub type gpgme_data_read_cb_t =
    Option<unsafe extern "C" fn(*mut c_void, *mut c_void, size_t) -> ssize_t>;
pub type gpgme_data_write_cb_t =
    Option<unsafe extern "C" fn(*mut c_void, *const c_void, size_t) -> ssize_t>;
pub type gpgme_data_seek_cb_t =
    Option<unsafe extern "C" fn(*mut c_void, gpgme_off_t, c_int) -> gpgme_off_t>;
pub type gpgme_data_release_cb_t = Option<unsafe extern "C" fn(*mut c_void)>;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct gpgme_data_cbs {
    pub read: gpgme_data_read_cb_t,
    pub write: gpgme_data_write_cb_t,
    pub seek: gpgme_data_seek_cb_t,
    pub release: gpgme_data_release_cb_t,
}
pub type gpgme_data_cbs_t = *mut gpgme_data_cbs;

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_invalid_key {
    pub next: gpgme_invalid_key_t,
    pub fpr: *mut c_char,
    pub reason: gpgme_error_t,
}
pub type gpgme_invalid_key_t = *mut _gpgme_invalid_key;

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_op_encrypt_result {
    pub invalid_recipients: gpgme_invalid_key_t,
}
pub type gpgme_encrypt_result_t = *mut _gpgme_op_encrypt_result;

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_recipient {
    pub next: gpgme_recipient_t,
    pub keyid: *mut c_char,
    _keyid: [c_char; 17],
    pub pubkey_algo: gpgme_pubkey_algo_t,
    pub status: gpgme_error_t,
}
pub type gpgme_recipient_t = *mut _gpgme_recipient;

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_op_decrypt_result {
    pub unsupported_algorithm: *mut c_char,
    pub bitfield: u32,
    pub recipients: gpgme_recipient_t,
    pub file_name: *mut c_char,
    pub session_key: *mut c_char,
    pub symkey_algo: *mut c_char,
}
pub type gpgme_decrypt_result_t = *mut _gpgme_op_decrypt_result;

impl _gpgme_op_decrypt_result {
    #[inline]
    pub fn wrong_key_usage(&self) -> bool {
        (self.bitfield & 0b0001) == 0b0001
    }

    #[inline]
    pub fn is_de_vs(&self) -> bool {
        (self.bitfield & 0b0010) == 0b0010
    }

    #[inline]
    pub fn is_mime(&self) -> bool {
        (self.bitfield & 0b0100) == 0b0100
    }

    #[inline]
    pub fn legacy_cipher_nomdc(&self) -> bool {
        (self.bitfield & 0b1000) == 0b1000
    }
}

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_new_signature {
    pub next: gpgme_new_signature_t,
    pub typ: gpgme_sig_mode_t,
    pub pubkey_algo: gpgme_pubkey_algo_t,
    pub hash_algo: gpgme_hash_algo_t,
    _class1: c_ulong,
    pub timestamp: c_long,
    pub fpr: *mut c_char,
    _class2: c_uint,
    pub sig_class: c_uint,
}
pub type gpgme_new_signature_t = *mut _gpgme_new_signature;

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_op_sign_result {
    pub invalid_signers: gpgme_invalid_key_t,
    pub signatures: gpgme_new_signature_t,
}
pub type gpgme_sign_result_t = *mut _gpgme_op_sign_result;

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_signature {
    pub next: gpgme_signature_t,
    pub summary: gpgme_sigsum_t,
    pub fpr: *mut c_char,
    pub status: gpgme_error_t,
    pub notations: gpgme_sig_notation_t,
    pub timestamp: c_ulong,
    pub exp_timestamp: c_ulong,
    pub bitfield: u32,
    pub validity: gpgme_validity_t,
    pub validity_reason: gpgme_error_t,
    pub pubkey_algo: gpgme_pubkey_algo_t,
    pub hash_algo: gpgme_hash_algo_t,
    pub pka_address: *mut c_char,
    pub key: gpgme_key_t,
}
pub type gpgme_signature_t = *mut _gpgme_signature;

impl _gpgme_signature {
    #[inline]
    pub fn wrong_key_usage(&self) -> bool {
        (self.bitfield & 0b0001) == 0b0001
    }

    #[inline]
    pub fn pka_trust(&self) -> c_uint {
        (self.bitfield & 0b0110) >> 1
    }

    #[inline]
    pub fn chain_model(&self) -> bool {
        (self.bitfield & 0b1000) == 0b1000
    }

    #[inline]
    pub fn is_de_vs(&self) -> bool {
        (self.bitfield & 0b1_0000) == 0b1_0000
    }
}

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_op_verify_result {
    pub signatures: gpgme_signature_t,
    pub file_name: *mut c_char,
    pub bitfield: u32,
}
pub type gpgme_verify_result_t = *mut _gpgme_op_verify_result;

impl _gpgme_op_verify_result {
    #[inline]
    pub fn is_mime(&self) -> bool {
        (self.bitfield & 0b0001) == 0b0001
    }
}

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_import_status {
    pub next: gpgme_import_status_t,
    pub fpr: *mut c_char,
    pub result: gpgme_error_t,
    pub status: c_uint,
}
pub type gpgme_import_status_t = *mut _gpgme_import_status;

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_op_import_result {
    pub considered: c_int,
    pub no_user_id: c_int,
    pub imported: c_int,
    pub imported_rsa: c_int,
    pub unchanged: c_int,
    pub new_user_ids: c_int,
    pub new_sub_keys: c_int,
    pub new_signatures: c_int,
    pub new_revocations: c_int,
    pub secret_read: c_int,
    pub secret_imported: c_int,
    pub secret_unchanged: c_int,
    pub skipped_new_keys: c_int,
    pub not_imported: c_int,
    pub imports: gpgme_import_status_t,
    pub skipped_v3_keys: c_int,
}
pub type gpgme_import_result_t = *mut _gpgme_op_import_result;

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_op_genkey_result {
    pub bitfield: u32,
    pub fpr: *mut c_char,
    pub pubkey: gpgme_data_t,
    pub seckey: gpgme_data_t,
}
pub type gpgme_genkey_result_t = *mut _gpgme_op_genkey_result;

impl _gpgme_op_genkey_result {
    #[inline]
    pub fn primary(&self) -> bool {
        (self.bitfield & 0b001) == 0b001
    }

    #[inline]
    pub fn sub(&self) -> bool {
        (self.bitfield & 0b010) == 0b010
    }

    #[inline]
    pub fn uid(&self) -> bool {
        (self.bitfield & 0b100) == 0b100
    }
}

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_op_keylist_result {
    pub bitfield: u32,
}
pub type gpgme_keylist_result_t = *mut _gpgme_op_keylist_result;

impl _gpgme_op_keylist_result {
    #[inline]
    pub fn truncated(&self) -> bool {
        (self.bitfield & 0b1) == 0b1
    }
}

pub type gpgme_assuan_data_cb_t =
    Option<unsafe extern "C" fn(*mut c_void, *const c_void, size_t) -> gpgme_error_t>;
pub type gpgme_assuan_inquire_cb_t = Option<
    unsafe extern "C" fn(
        *mut c_void,
        *const c_char,
        *const c_char,
        *mut gpgme_data_t,
    ) -> gpgme_error_t,
>;
pub type gpgme_assuan_status_cb_t =
    Option<unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> gpgme_error_t>;

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_op_vfs_mount_result {
    pub mount_dir: *mut c_char,
}
pub type gpgme_vfs_mount_result_t = *mut _gpgme_op_vfs_mount_result;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct gpgme_conf_arg {
    pub next: gpgme_conf_arg_t,
    pub no_arg: c_uint,
    pub value: uintptr_t,
}
pub type gpgme_conf_arg_t = *mut gpgme_conf_arg;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct gpgme_conf_opt {
    pub next: gpgme_conf_opt_t,
    pub name: *mut c_char,
    pub flags: c_uint,
    pub level: gpgme_conf_level_t,
    pub description: *mut c_char,
    pub typ: gpgme_conf_type_t,
    pub alt_type: gpgme_conf_type_t,
    pub argname: *mut c_char,
    pub default_value: gpgme_conf_arg_t,
    pub default_description: *mut c_char,
    pub no_arg_value: gpgme_conf_arg_t,
    pub no_arg_description: *mut c_char,
    pub value: gpgme_conf_arg_t,
    pub change_value: c_int,
    pub new_value: gpgme_conf_arg_t,
    pub user_data: *mut c_void,
}
pub type gpgme_conf_opt_t = *mut gpgme_conf_opt;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct gpgme_conf_comp {
    pub next: gpgme_conf_comp_t,
    _last_opt_p: *mut gpgme_conf_opt_t,
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub program_name: *mut c_char,
    pub options: gpgme_conf_opt_t,
}
pub type gpgme_conf_comp_t = *mut gpgme_conf_comp;

#[repr(C)]
#[non_exhaustive]
pub struct _gpgme_op_query_swdb_result {
    pub next: *mut _gpgme_op_query_swdb_result,
    pub name: *mut c_char,
    pub iversion: *mut c_char,
    pub created: c_ulong,
    pub retrieved: c_ulong,
    bitfield: u32,
    pub version: *mut c_char,
    pub reldate: c_ulong,
}

impl _gpgme_op_query_swdb_result {
    #[inline]
    pub fn warning(&self) -> bool {
        (self.bitfield & 0b0000_0001) == 0b0000_0001
    }

    #[inline]
    pub fn update(&self) -> bool {
        (self.bitfield & 0b0000_0010) == 0b0000_0010
    }

    #[inline]
    pub fn urgent(&self) -> bool {
        (self.bitfield & 0b0000_0100) == 0b0000_0100
    }

    #[inline]
    pub fn noinfo(&self) -> bool {
        (self.bitfield & 0b0000_1000) == 0b0000_1000
    }

    #[inline]
    pub fn unknown(&self) -> bool {
        (self.bitfield & 0b0001_0000) == 0b0001_0000
    }

    #[inline]
    pub fn tooold(&self) -> bool {
        (self.bitfield & 0b0010_0000) == 0b0010_0000
    }

    #[inline]
    pub fn error(&self) -> bool {
        (self.bitfield & 0b0100_0000) == 0b0100_0000
    }
}
pub type gpgme_query_swdb_result_t = *mut _gpgme_op_query_swdb_result;

#[cfg_attr(
    all(windows, feature = "windows_raw_dylib"),
    link(name = "libgpgme-11.dll", kind = "raw-dylib", modifiers = "+verbatim")
)]
extern "C" {
    pub fn gpgme_set_global_flag(name: *const c_char, value: *const c_char) -> c_int;

    pub fn gpgme_check_version(req_version: *const c_char) -> *const c_char;
    pub fn gpgme_check_version_internal(
        req_version: *const c_char,
        offset_sig_validity: size_t,
    ) -> *const c_char;

    pub fn gpgme_get_dirinfo(what: *const c_char) -> *const c_char;

    pub fn gpgme_get_engine_info(engine_info: *mut gpgme_engine_info_t) -> gpgme_error_t;
    pub fn gpgme_set_engine_info(
        proto: gpgme_protocol_t,
        file_name: *const c_char,
        home_dir: *const c_char,
    ) -> gpgme_error_t;

    pub fn gpgme_engine_check_version(proto: gpgme_protocol_t) -> gpgme_error_t;

    pub fn gpgme_result_ref(result: *mut c_void);
    pub fn gpgme_result_unref(result: *mut c_void);

    pub fn gpgme_new(ctx: *mut gpgme_ctx_t) -> gpgme_error_t;
    pub fn gpgme_release(ctx: gpgme_ctx_t);

    pub fn gpgme_set_ctx_flag(
        ctx: gpgme_ctx_t,
        name: *const c_char,
        value: *const c_char,
    ) -> gpgme_error_t;
    pub fn gpgme_get_ctx_flag(ctx: gpgme_ctx_t, name: *const c_char) -> *const c_char;

    pub fn gpgme_set_protocol(ctx: gpgme_ctx_t, proto: gpgme_protocol_t) -> gpgme_error_t;
    pub fn gpgme_get_protocol(ctx: gpgme_ctx_t) -> gpgme_protocol_t;

    pub fn gpgme_set_sub_protocol(ctx: gpgme_ctx_t, proto: gpgme_protocol_t) -> gpgme_error_t;
    pub fn gpgme_get_sub_protocol(ctx: gpgme_ctx_t) -> gpgme_protocol_t;

    pub fn gpgme_get_protocol_name(proto: gpgme_protocol_t) -> *const c_char;

    pub fn gpgme_set_armor(ctx: gpgme_ctx_t, yes: c_int);
    pub fn gpgme_get_armor(ctx: gpgme_ctx_t) -> c_int;

    pub fn gpgme_set_textmode(ctx: gpgme_ctx_t, yes: c_int);
    pub fn gpgme_get_textmode(ctx: gpgme_ctx_t) -> c_int;

    pub fn gpgme_set_include_certs(ctx: gpgme_ctx_t, nr_of_certs: c_int);
    pub fn gpgme_get_include_certs(ctx: gpgme_ctx_t) -> c_int;

    pub fn gpgme_set_offline(ctx: gpgme_ctx_t, yes: c_int);
    pub fn gpgme_get_offline(ctx: gpgme_ctx_t) -> c_int;

    pub fn gpgme_set_keylist_mode(ctx: gpgme_ctx_t, mode: gpgme_keylist_mode_t) -> gpgme_error_t;
    pub fn gpgme_get_keylist_mode(ctx: gpgme_ctx_t) -> gpgme_keylist_mode_t;

    pub fn gpgme_set_pinentry_mode(ctx: gpgme_ctx_t, mode: gpgme_pinentry_mode_t) -> gpgme_error_t;
    pub fn gpgme_get_pinentry_mode(ctx: gpgme_ctx_t) -> gpgme_pinentry_mode_t;

    pub fn gpgme_set_passphrase_cb(
        ctx: gpgme_ctx_t,
        cb: gpgme_passphrase_cb_t,
        hook_value: *mut c_void,
    );
    pub fn gpgme_get_passphrase_cb(
        ctx: gpgme_ctx_t,
        cb: *mut gpgme_passphrase_cb_t,
        hood_value: *mut *mut c_void,
    );

    pub fn gpgme_set_progress_cb(
        ctx: gpgme_ctx_t,
        cb: gpgme_progress_cb_t,
        hook_value: *mut c_void,
    );
    pub fn gpgme_get_progress_cb(
        ctx: gpgme_ctx_t,
        cb: *mut gpgme_progress_cb_t,
        hook_value: *mut *mut c_void,
    );

    pub fn gpgme_set_status_cb(ctx: gpgme_ctx_t, cb: gpgme_status_cb_t, hook_value: *mut c_void);
    pub fn gpgme_get_status_cb(
        ctx: gpgme_ctx_t,
        cb: *mut gpgme_status_cb_t,
        hook_value: *mut *mut c_void,
    );

    pub fn gpgme_set_locale(
        ctx: gpgme_ctx_t,
        category: c_int,
        value: *const c_char,
    ) -> gpgme_error_t;

    pub fn gpgme_ctx_get_engine_info(ctx: gpgme_ctx_t) -> gpgme_engine_info_t;
    pub fn gpgme_ctx_set_engine_info(
        ctx: gpgme_ctx_t,
        proto: gpgme_protocol_t,
        file_name: *const c_char,
        home_dir: *const c_char,
    ) -> gpgme_error_t;

    pub fn gpgme_pubkey_algo_string(subkey: gpgme_subkey_t) -> *mut c_char;
    pub fn gpgme_pubkey_algo_name(algo: gpgme_pubkey_algo_t) -> *const c_char;
    pub fn gpgme_hash_algo_name(algo: gpgme_hash_algo_t) -> *const c_char;

    pub fn gpgme_addrspec_from_uid(uid: *const c_char) -> *mut c_char;

    pub fn gpgme_signers_clear(ctx: gpgme_ctx_t);
    pub fn gpgme_signers_add(ctx: gpgme_ctx_t, key: gpgme_key_t) -> gpgme_error_t;
    pub fn gpgme_signers_count(ctx: gpgme_ctx_t) -> c_uint;
    pub fn gpgme_signers_enum(ctx: gpgme_ctx_t, seq: c_int) -> gpgme_key_t;

    pub fn gpgme_sig_notation_clear(ctx: gpgme_ctx_t);
    pub fn gpgme_sig_notation_add(
        ctx: gpgme_ctx_t,
        name: *const c_char,
        value: *const c_char,
        flags: gpgme_sig_notation_flags_t,
    ) -> gpgme_error_t;
    pub fn gpgme_sig_notation_get(ctx: gpgme_ctx_t) -> gpgme_sig_notation_t;

    pub fn gpgme_set_sender(ctx: gpgme_ctx_t, address: *const c_char) -> gpgme_error_t;
    pub fn gpgme_get_sender(ctx: gpgme_ctx_t) -> *const c_char;

    pub fn gpgme_set_io_cbs(ctx: gpgme_ctx_t, io_cbs: gpgme_io_cbs_t);
    pub fn gpgme_get_io_cbs(ctx: gpgme_ctx_t, io_cbs: gpgme_io_cbs_t);

    pub fn gpgme_io_read(fd: c_int, buffer: *mut c_void, count: size_t) -> ssize_t;
    pub fn gpgme_io_write(fd: c_int, buffer: *const c_void, count: size_t) -> ssize_t;
    pub fn gpgme_io_writen(fd: c_int, buffer: *const c_void, count: size_t) -> c_int;

    pub fn gpgme_wait(ctx: gpgme_ctx_t, status: *mut gpgme_error_t, hang: c_int) -> gpgme_ctx_t;
    pub fn gpgme_wait_ext(
        ctx: gpgme_ctx_t,
        status: *mut gpgme_error_t,
        op_err: *mut gpgme_error_t,
        hang: c_int,
    ) -> gpgme_ctx_t;

    pub fn gpgme_data_read(dh: gpgme_data_t, buffer: *mut c_void, size: size_t) -> ssize_t;
    pub fn gpgme_data_write(dh: gpgme_data_t, buffer: *const c_void, size: size_t) -> ssize_t;
    pub fn gpgme_data_seek(dh: gpgme_data_t, offset: gpgme_off_t, whence: c_int) -> gpgme_off_t;

    pub fn gpgme_data_new(r_dh: *mut gpgme_data_t) -> gpgme_error_t;
    pub fn gpgme_data_release(dh: gpgme_data_t);

    pub fn gpgme_data_new_from_mem(
        r_dh: *mut gpgme_data_t,
        buffer: *const c_char,
        size: size_t,
        copy: c_int,
    ) -> gpgme_error_t;
    pub fn gpgme_data_release_and_get_mem(dh: gpgme_data_t, r_len: *mut size_t) -> *mut c_char;
    pub fn gpgme_free(buffer: *mut c_void);

    pub fn gpgme_data_new_from_cbs(
        dh: *mut gpgme_data_t,
        cbs: gpgme_data_cbs_t,
        handle: *mut c_void,
    ) -> gpgme_error_t;
    pub fn gpgme_data_new_from_fd(dh: *mut gpgme_data_t, fd: c_int) -> gpgme_error_t;

    pub fn gpgme_data_new_from_stream(dh: *mut gpgme_data_t, stream: *mut FILE) -> gpgme_error_t;

    pub fn gpgme_data_get_encoding(dh: gpgme_data_t) -> gpgme_data_encoding_t;
    pub fn gpgme_data_set_encoding(dh: gpgme_data_t, enc: gpgme_data_encoding_t) -> gpgme_error_t;

    pub fn gpgme_data_get_file_name(dh: gpgme_data_t) -> *mut c_char;
    pub fn gpgme_data_set_file_name(dh: gpgme_data_t, file_name: *const c_char) -> gpgme_error_t;

    pub fn gpgme_data_set_flag(
        dh: gpgme_data_t,
        name: *const c_char,
        value: *const c_char,
    ) -> gpgme_error_t;

    pub fn gpgme_data_identify(dh: gpgme_data_t, _reserved: c_int) -> gpgme_data_type_t;

    pub fn gpgme_data_new_from_file(
        r_dh: *mut gpgme_data_t,
        fname: *const c_char,
        copy: c_int,
    ) -> gpgme_error_t;
    pub fn gpgme_data_new_from_filepart(
        r_dh: *mut gpgme_data_t,
        fname: *const c_char,
        fp: *mut FILE,
        offset: off_t,
        length: size_t,
    ) -> gpgme_error_t;

    pub fn gpgme_get_key(
        ctx: gpgme_ctx_t,
        fpr: *const c_char,
        r_key: *mut gpgme_key_t,
        secret: c_int,
    ) -> gpgme_error_t;
    pub fn gpgme_key_ref(key: gpgme_key_t);
    pub fn gpgme_key_unref(key: gpgme_key_t);
    pub fn gpgme_key_release(key: gpgme_key_t);

    pub fn gpgme_cancel(ctx: gpgme_ctx_t) -> gpgme_error_t;
    pub fn gpgme_cancel_async(ctx: gpgme_ctx_t) -> gpgme_error_t;

    pub fn gpgme_op_encrypt_result(ctx: gpgme_ctx_t) -> gpgme_encrypt_result_t;
    pub fn gpgme_op_encrypt_start(
        ctx: gpgme_ctx_t,
        recp: *mut gpgme_key_t,
        flags: gpgme_encrypt_flags_t,
        plain: gpgme_data_t,
        cipher: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_encrypt(
        ctx: gpgme_ctx_t,
        recp: *mut gpgme_key_t,
        flags: gpgme_encrypt_flags_t,
        plain: gpgme_data_t,
        cipher: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_encrypt_ext_start(
        ctx: gpgme_ctx_t,
        recp: *mut gpgme_key_t,
        recpstring: *const c_char,
        flags: gpgme_encrypt_flags_t,
        plain: gpgme_data_t,
        cipher: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_encrypt_ext(
        ctx: gpgme_ctx_t,
        recp: *mut gpgme_key_t,
        recpstring: *const c_char,
        flags: gpgme_encrypt_flags_t,
        plain: gpgme_data_t,
        cipher: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_encrypt_sign_start(
        ctx: gpgme_ctx_t,
        recp: *mut gpgme_key_t,
        flags: gpgme_encrypt_flags_t,
        plain: gpgme_data_t,
        cipher: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_encrypt_sign(
        ctx: gpgme_ctx_t,
        recp: *mut gpgme_key_t,
        flags: gpgme_encrypt_flags_t,
        plain: gpgme_data_t,
        cipher: gpgme_data_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_decrypt_result(ctx: gpgme_ctx_t) -> gpgme_decrypt_result_t;
    pub fn gpgme_op_decrypt_start(
        ctx: gpgme_ctx_t,
        cipher: gpgme_data_t,
        plain: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_decrypt(
        ctx: gpgme_ctx_t,
        cipher: gpgme_data_t,
        plain: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_decrypt_verify_start(
        ctx: gpgme_ctx_t,
        cipher: gpgme_data_t,
        plain: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_decrypt_verify(
        ctx: gpgme_ctx_t,
        cipher: gpgme_data_t,
        plain: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_decrypt_ext_start(
        ctx: gpgme_ctx_t,
        flags: gpgme_decrypt_flags_t,
        cipher: gpgme_data_t,
        plain: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_decrypt_ext(
        ctx: gpgme_ctx_t,
        flags: gpgme_decrypt_flags_t,
        cipher: gpgme_data_t,
        plain: gpgme_data_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_sign_result(ctx: gpgme_ctx_t) -> gpgme_sign_result_t;
    pub fn gpgme_op_sign_start(
        ctx: gpgme_ctx_t,
        plain: gpgme_data_t,
        sig: gpgme_data_t,
        mode: gpgme_sig_mode_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_sign(
        ctx: gpgme_ctx_t,
        plain: gpgme_data_t,
        sig: gpgme_data_t,
        mode: gpgme_sig_mode_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_encrypt_sign_ext_start(
        ctx: gpgme_ctx_t,
        recp: *mut gpgme_key_t,
        recpstring: *const c_char,
        flags: gpgme_encrypt_flags_t,
        plain: gpgme_data_t,
        cipher: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_encrypt_sign_ext(
        ctx: gpgme_ctx_t,
        recp: *mut gpgme_key_t,
        recpstring: *const c_char,
        flags: gpgme_encrypt_flags_t,
        plain: gpgme_data_t,
        cipher: gpgme_data_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_verify_result(ctx: gpgme_ctx_t) -> gpgme_verify_result_t;
    pub fn gpgme_op_verify_start(
        ctx: gpgme_ctx_t,
        sig: gpgme_data_t,
        signed_text: gpgme_data_t,
        plaintext: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_verify(
        ctx: gpgme_ctx_t,
        sig: gpgme_data_t,
        signed_text: gpgme_data_t,
        plaintext: gpgme_data_t,
    ) -> gpgme_error_t;
    // 1.19
    pub fn gpgme_op_verify_ext_start(
        ctx: gpgme_ctx_t,
        flags: gpgme_verify_flags_t,
        sig: gpgme_data_t,
        signed_text: gpgme_data_t,
        plaintext: gpgme_data_t,
    ) -> gpgme_error_t;
    // 1.19
    pub fn gpgme_op_verify_ext(
        ctx: gpgme_ctx_t,
        flags: gpgme_verify_flags_t,
        sig: gpgme_data_t,
        signed_text: gpgme_data_t,
        plaintext: gpgme_data_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_import_result(ctx: gpgme_ctx_t) -> gpgme_import_result_t;
    pub fn gpgme_op_import_start(ctx: gpgme_ctx_t, keydata: gpgme_data_t) -> gpgme_error_t;
    pub fn gpgme_op_import(ctx: gpgme_ctx_t, keydata: gpgme_data_t) -> gpgme_error_t;

    pub fn gpgme_op_import_keys_start(ctx: gpgme_ctx_t, keys: *mut gpgme_key_t) -> gpgme_error_t;
    pub fn gpgme_op_import_keys(ctx: gpgme_ctx_t, keys: *mut gpgme_key_t) -> gpgme_error_t;

    // 1.17
    pub fn gpgme_op_receive_keys_start(
        ctx: gpgme_ctx_t,
        keyids: *const *const c_char,
    ) -> gpgme_error_t;
    // 1.17
    pub fn gpgme_op_receive_keys(ctx: gpgme_ctx_t, keyids: *const *const c_char) -> gpgme_error_t;

    pub fn gpgme_op_export_start(
        ctx: gpgme_ctx_t,
        pattern: *const c_char,
        mode: gpgme_export_mode_t,
        keydata: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_export(
        ctx: gpgme_ctx_t,
        pattern: *const c_char,
        mode: gpgme_export_mode_t,
        keydata: gpgme_data_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_export_ext_start(
        ctx: gpgme_ctx_t,
        pattern: *mut *const c_char,
        mode: gpgme_export_mode_t,
        keydata: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_export_ext(
        ctx: gpgme_ctx_t,
        pattern: *mut *const c_char,
        mode: gpgme_export_mode_t,
        keydata: gpgme_data_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_export_keys_start(
        ctx: gpgme_ctx_t,
        keys: *mut gpgme_key_t,
        mode: gpgme_export_mode_t,
        keydata: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_export_keys(
        ctx: gpgme_ctx_t,
        keys: *mut gpgme_key_t,
        mode: gpgme_export_mode_t,
        keydata: gpgme_data_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_genkey_result(ctx: gpgme_ctx_t) -> gpgme_genkey_result_t;
    pub fn gpgme_op_genkey_start(
        ctx: gpgme_ctx_t,
        parms: *const c_char,
        pubkey: gpgme_data_t,
        seckey: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_genkey(
        ctx: gpgme_ctx_t,
        parms: *const c_char,
        pubkey: gpgme_data_t,
        seckey: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_createkey_start(
        ctx: gpgme_ctx_t,
        userid: *const c_char,
        algo: *const c_char,
        reserved: c_ulong,
        expires: c_ulong,
        certkey: gpgme_key_t,
        flags: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_createkey(
        ctx: gpgme_ctx_t,
        userid: *const c_char,
        algo: *const c_char,
        reserved: c_ulong,
        expires: c_ulong,
        certkey: gpgme_key_t,
        flags: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_createsubkey_start(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        algo: *const c_char,
        reserved: c_ulong,
        expires: c_ulong,
        flags: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_createsubkey(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        algo: *const c_char,
        reserved: c_ulong,
        expires: c_ulong,
        flags: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_adduid_start(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        userid: *const c_char,
        reserved: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_adduid(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        userid: *const c_char,
        reserved: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_revuid_start(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        userid: *const c_char,
        reserved: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_revuid(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        userid: *const c_char,
        reserved: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_set_uid_flag_start(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        userid: *const c_char,
        name: *const c_char,
        value: *const c_char,
    ) -> gpgme_error_t;
    pub fn gpgme_op_set_uid_flag(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        userid: *const c_char,
        name: *const c_char,
        value: *const c_char,
    ) -> gpgme_error_t;
    // 1.15
    pub fn gpgme_op_setexpire_start(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        expires: c_ulong,
        subfprs: *const c_char,
        reserved: c_uint,
    ) -> gpgme_error_t;
    // 1.15
    pub fn gpgme_op_setexpire(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        expires: c_ulong,
        subfprs: *const c_char,
        reserved: c_uint,
    ) -> gpgme_error_t;

    pub fn gpgme_op_delete_start(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        allow_secret: c_int,
    ) -> gpgme_error_t;
    pub fn gpgme_op_delete(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        allow_secret: c_int,
    ) -> gpgme_error_t;
    pub fn gpgme_op_delete_ext_start(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        flags: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_delete_ext(ctx: gpgme_ctx_t, key: gpgme_key_t, flags: c_uint) -> gpgme_error_t;

    pub fn gpgme_op_keysign_start(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        userid: *const c_char,
        expires: c_ulong,
        flags: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_keysign(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        userid: *const c_char,
        expires: c_ulong,
        flags: c_uint,
    ) -> gpgme_error_t;

    // 1.15
    pub fn gpgme_op_revsig_start(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        signing_key: gpgme_key_t,
        userid: *const c_char,
        flags: c_uint,
    ) -> gpgme_error_t;
    // 1.15
    pub fn gpgme_op_revsig(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        signing_key: gpgme_key_t,
        userid: *const c_char,
        flags: c_uint,
    ) -> gpgme_error_t;

    pub fn gpgme_op_interact_start(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        flags: c_uint,
        fnc: gpgme_interact_cb_t,
        fnc_value: *mut c_void,
        out: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_interact(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        flags: c_uint,
        fnc: gpgme_interact_cb_t,
        fnc_value: *mut c_void,
        out: gpgme_data_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_edit_start(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        fnc: gpgme_edit_cb_t,
        fnc_value: *mut c_void,
        out: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_edit(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        fnc: gpgme_edit_cb_t,
        fnc_value: *mut c_void,
        out: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_card_edit_start(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        fnc: gpgme_edit_cb_t,
        fnc_value: *mut c_void,
        out: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_card_edit(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        fnc: gpgme_edit_cb_t,
        fnc_value: *mut c_void,
        out: gpgme_data_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_tofu_policy_start(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        policy: gpgme_tofu_policy_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_tofu_policy(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        policy: gpgme_tofu_policy_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_spawn_start(
        ctx: gpgme_ctx_t,
        file: *const c_char,
        argv: *mut *const c_char,
        datain: gpgme_data_t,
        dataout: gpgme_data_t,
        dataerr: gpgme_data_t,
        flags: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_spawn(
        ctx: gpgme_ctx_t,
        file: *const c_char,
        argv: *mut *const c_char,
        datain: gpgme_data_t,
        dataout: gpgme_data_t,
        dataerr: gpgme_data_t,
        flags: c_uint,
    ) -> gpgme_error_t;

    pub fn gpgme_op_keylist_result(ctx: gpgme_ctx_t) -> gpgme_keylist_result_t;
    pub fn gpgme_op_keylist_start(
        ctx: gpgme_ctx_t,
        pattern: *const c_char,
        secret_only: c_int,
    ) -> gpgme_error_t;
    pub fn gpgme_op_keylist_ext_start(
        ctx: gpgme_ctx_t,
        pattern: *mut *const c_char,
        secret_only: c_int,
        _reserved: c_int,
    ) -> gpgme_error_t;
    pub fn gpgme_op_keylist_from_data_start(
        ctx: gpgme_ctx_t,
        data: gpgme_data_t,
        reserved: c_int,
    ) -> gpgme_error_t;
    pub fn gpgme_op_keylist_next(ctx: gpgme_ctx_t, r_key: *mut gpgme_key_t) -> gpgme_error_t;
    pub fn gpgme_op_keylist_end(ctx: gpgme_ctx_t) -> gpgme_error_t;

    pub fn gpgme_op_passwd_start(
        ctx: gpgme_ctx_t,
        key: gpgme_key_t,
        flags: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_passwd(ctx: gpgme_ctx_t, key: gpgme_key_t, flags: c_uint) -> gpgme_error_t;

    pub fn gpgme_op_getauditlog_start(
        ctx: gpgme_ctx_t,
        output: gpgme_data_t,
        flags: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_getauditlog(
        ctx: gpgme_ctx_t,
        output: gpgme_data_t,
        flags: c_uint,
    ) -> gpgme_error_t;

    pub fn gpgme_op_assuan_transact_start(
        ctx: gpgme_ctx_t,
        command: *const c_char,
        data_cb: gpgme_assuan_data_cb_t,
        data_cb_value: *mut c_void,
        inq_cb: gpgme_assuan_inquire_cb_t,
        inq_cb_value: *mut c_void,
        stat_cb: gpgme_assuan_status_cb_t,
        stat_cb_value: *mut c_void,
    ) -> gpgme_error_t;
    pub fn gpgme_op_assuan_transact_ext(
        ctx: gpgme_ctx_t,
        command: *const c_char,
        data_cb: gpgme_assuan_data_cb_t,
        data_cb_value: *mut c_void,
        inq_cb: gpgme_assuan_inquire_cb_t,
        inq_cb_value: *mut c_void,
        stat_cb: gpgme_assuan_status_cb_t,
        stat_cb_value: *mut c_void,
        op_err: *mut gpgme_error_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_vfs_mount_result(ctx: gpgme_ctx_t) -> gpgme_vfs_mount_result_t;
    pub fn gpgme_op_vfs_mount(
        ctx: gpgme_ctx_t,
        container_file: *const c_char,
        mount_dir: *const c_char,
        flags: c_uint,
        op_err: *mut gpgme_error_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_vfs_create(
        ctx: gpgme_ctx_t,
        recp: *mut gpgme_key_t,
        container_file: *const c_char,
        flags: c_uint,
        op_err: *mut gpgme_error_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_query_swdb(
        ctx: gpgme_ctx_t,
        name: *const c_char,
        iversion: *const c_char,
        _reserved: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_query_swdb_result(ctx: gpgme_ctx_t) -> gpgme_query_swdb_result_t;

    pub fn gpgme_conf_arg_new(
        arg_p: *mut gpgme_conf_arg_t,
        arg_type: gpgme_conf_type_t,
        value: *const c_void,
    ) -> gpgme_error_t;
    pub fn gpgme_conf_arg_release(arg: gpgme_conf_arg_t, arg_type: gpgme_conf_type_t);
    pub fn gpgme_conf_opt_change(
        opt: gpgme_conf_opt_t,
        reset: c_int,
        arg: gpgme_conf_arg_t,
    ) -> gpgme_error_t;
    pub fn gpgme_conf_release(conf: gpgme_conf_comp_t);

    pub fn gpgme_op_conf_load(ctx: gpgme_ctx_t, conf_p: *mut gpgme_conf_comp_t) -> gpgme_error_t;
    pub fn gpgme_op_conf_save(ctx: gpgme_ctx_t, comp: gpgme_conf_comp_t) -> gpgme_error_t;

    pub fn gpgme_key_from_uid(key: *mut gpgme_key_t, name: *const c_char) -> gpgme_error_t;
}
