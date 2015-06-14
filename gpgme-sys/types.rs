#![allow(raw_pointer_derive)]
extern crate libc;
extern crate libgpg_error_sys;

use libc::{c_void, c_char, c_uchar, c_short, c_ushort, c_int, c_uint, c_long, c_ulong, ssize_t, size_t};

use consts::*;

pub use libgpg_error_sys::gpg_error_t as gpgme_error_t;

#[cfg(all(target_os = "windows", target_arch = "x86"))]
pub type gpgme_off_t = i32;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub type gpgme_off_t = i64;
#[cfg(not(target_os = "windows"))]
pub type gpgme_off_t = libc::off_t;

pub type gpgme_ssize_t = libc::ssize_t;

pub enum gpgme_context {}
pub type gpgme_ctx_t = *mut gpgme_context;

pub enum gpgme_data {}
pub type gpgme_data_t = *mut gpgme_data;

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_sig_notation {
  pub next: *mut _gpgme_sig_notation,
  pub name: *mut c_char,
  pub value: *mut c_char,
  pub name_len: c_int,
  pub value_len: c_int,
  pub flags: gpgme_sig_notation_flags_t,
  pub bitfield: u32
}
pub type gpgme_sig_notation_t = *mut _gpgme_sig_notation;

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_engine_info {
    pub next: *mut _gpgme_engine_info,
    pub protocol: gpgme_protocol_t,
    pub file_name: *mut c_char,
    pub version: *mut c_char,
    pub req_version: *mut c_char,
    pub home_dir: *mut c_char
}
pub type gpgme_engine_info_t = *mut _gpgme_engine_info;

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_subkey {
    pub next: *mut _gpgme_subkey,
    pub bitfield: u32,
    pub pubkey_algo: gpgme_pubkey_algo_t,
    pub length: c_uint,
    pub keyid: *mut c_char,
    _keyid: [c_char; 17],
    pub fpr: *mut c_char,
    pub timestamp: c_long,
    pub expires: c_long,
    pub card_number: *mut c_char
}
pub type gpgme_subkey_t = *mut _gpgme_subkey;

impl _gpgme_subkey {
    pub fn revoked(&self) -> bool {
        (self.bitfield & 0x1) == 0x1
    }
    pub fn expired(&self) -> bool {
        (self.bitfield & 0x2) == 0x2
    }
    pub fn disabled(&self) -> bool {
        (self.bitfield & 0x4) == 0x4
    }
    pub fn invalid(&self) -> bool {
        (self.bitfield & 0x8) == 0x8
    }
    pub fn can_encrypt(&self) -> bool {
        (self.bitfield & 0x10) == 0x10
    }
    pub fn can_sign(&self) -> bool {
        (self.bitfield & 0x20) == 0x20
    }
    pub fn can_certify(&self) -> bool {
        (self.bitfield & 0x40) == 0x40
    }
    pub fn secret(&self) -> bool {
        (self.bitfield & 0x80) == 0x80
    }
    pub fn can_authenticate(&self) -> bool {
        (self.bitfield & 0x100) == 0x100
    }
    pub fn is_qualified(&self) -> bool {
        (self.bitfield & 0x200) == 0x200
    }
    pub fn is_cardkey(&self) -> bool {
        (self.bitfield & 0x400) == 0x400
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_key_sig {
    pub next: *mut _gpgme_key_sig,
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
    _last_notation: gpgme_sig_notation_t
}
pub type gpgme_key_sig_t = *mut _gpgme_key_sig;

impl _gpgme_key_sig {
    pub fn revoked(&self) -> bool {
        (self.bitfield & 0x1) == 0x1
    }
    pub fn expired(&self) -> bool {
        (self.bitfield & 0x2) == 0x2
    }
    pub fn invalid(&self) -> bool {
        (self.bitfield & 0x4) == 0x4
    }
    pub fn exportable(&self) -> bool {
        (self.bitfield & 0x8) == 0x8
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_user_id {
    pub next: *mut _gpgme_user_id,
    pub bitfield: u32,
    pub validity: gpgme_validity_t,
    pub uid: *mut c_char,
    pub name: *mut c_char,
    pub email: *mut c_char,
    pub comment: *mut c_char,
    pub signatures: gpgme_key_sig_t,
    _last_keysig: gpgme_key_sig_t
}
pub type gpgme_user_id_t = *mut _gpgme_user_id;

impl _gpgme_user_id {
    pub fn revoked(&self) -> bool {
        (self.bitfield & 0x1) == 0x1
    }
    pub fn invalid(&self) -> bool {
        (self.bitfield & 0x2) == 0x2
    }
}

#[repr(C)]
#[derive(Clone)]
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
    pub keylist_mode: gpgme_keylist_mode_t
}
pub type gpgme_key_t = *mut _gpgme_key;

impl _gpgme_key {
    pub fn revoked(&self) -> bool {
        (self.bitfield & 0x1) == 0x1
    }
    pub fn expired(&self) -> bool {
        (self.bitfield & 0x2) == 0x2
    }
    pub fn disabled(&self) -> bool {
        (self.bitfield & 0x4) == 0x4
    }
    pub fn invalid(&self) -> bool {
        (self.bitfield & 0x8) == 0x8
    }
    pub fn can_encrypt(&self) -> bool {
        (self.bitfield & 0x10) == 0x10
    }
    pub fn can_sign(&self) -> bool {
        (self.bitfield & 0x20) == 0x20
    }
    pub fn can_certify(&self) -> bool {
        (self.bitfield & 0x40) == 0x40
    }
    pub fn secret(&self) -> bool {
        (self.bitfield & 0x80) == 0x80
    }
    pub fn can_authenticate(&self) -> bool {
        (self.bitfield & 0x100) == 0x100
    }
    pub fn is_qualified(&self) -> bool {
        (self.bitfield & 0x200) == 0x200
    }
}

pub type gpgme_passphrase_cb_t = Option<extern fn(*mut c_void, *const c_char, *const c_char, c_int, c_int)>;
pub type gpgme_progress_cb_t = Option<extern fn(*mut c_void, *const c_char, c_int, c_int, c_int)>;
pub type gpgme_edit_cb_t = Option<extern fn(*mut c_void, gpgme_status_code_t, *const c_char, c_int) -> gpgme_error_t>;

pub type gpgme_io_cb_t = Option<extern fn(*mut c_void, c_int) -> gpgme_error_t>;
pub type gpgme_register_io_cb_t = Option<extern fn(*mut c_void, c_int, c_int, gpgme_io_cb_t, *mut c_void, *mut *mut c_void) -> gpgme_error_t>;
pub type gpgme_remove_io_cb_t = Option<extern fn(*mut c_void)>;

#[repr(C)]
#[derive(Clone)]
pub struct gpgme_io_event_done_data {
    pub err: gpgme_error_t,
    pub op_err: gpgme_error_t
}
pub type gpgme_io_event_done_data_t = *mut gpgme_io_event_done_data;

pub type gpgme_event_io_cb_t = Option<extern fn(*mut c_void, gpgme_event_io_t, *mut c_void)>;

#[repr(C)]
#[derive(Clone)]
pub struct gpgme_io_cbs {
    pub add: gpgme_register_io_cb_t,
    pub add_priv: *mut c_void,
    pub remove: gpgme_remove_io_cb_t,
    pub event: gpgme_event_io_cb_t,
    pub event_priv: *mut c_void
}
pub type gpgme_io_cbs_t = *mut gpgme_io_cbs;

pub type gpgme_data_read_cb_t = Option<extern fn(*mut c_void, *mut c_void, size_t) -> ssize_t>;
pub type gpgme_data_write_cb_t = Option<extern fn(*mut c_void, *const c_void, size_t) -> ssize_t>;
pub type gpgme_data_seek_cb_t = Option<extern fn(*mut c_void, libc::off_t, c_int) -> libc::off_t>;
pub type gpgme_data_release_cb_t = Option<extern fn(*mut c_void)>;

#[repr(C)]
#[derive(Clone)]
pub struct gpgme_data_cbs {
  pub read: gpgme_data_read_cb_t,
  pub write: gpgme_data_write_cb_t,
  pub seek: gpgme_data_seek_cb_t,
  pub release: gpgme_data_release_cb_t
}
pub type gpgme_data_cbs_t = *mut gpgme_data_cbs;

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_invalid_key {
  pub next: *mut _gpgme_invalid_key,
  pub fpr: *mut c_char,
  pub reason: gpgme_error_t
}
pub type gpgme_invalid_key_t = *mut _gpgme_invalid_key;

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_op_encrypt_result {
  pub invalid_recipients: gpgme_invalid_key_t
}
pub type gpgme_encrypt_result_t = *mut _gpgme_op_encrypt_result;

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_recipient {
    pub next: *mut _gpgme_recipient,
    pub keyid: *mut c_char,
    _keyid: [c_char; 17],
    pub pubkey_algo: gpgme_pubkey_algo_t,
    pub status: gpgme_error_t
}
pub type gpgme_recipient_t = *mut _gpgme_recipient;

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_op_decrypt_result {
    pub unsupported_algorithm: *mut c_char,
    pub bitfield: u32,
    pub recipients: gpgme_recipient_t,
    pub file_name: *mut c_char
}
pub type gpgme_decrypt_result_t = *mut _gpgme_op_decrypt_result;

impl _gpgme_op_decrypt_result {
    pub fn wrong_key_usage(&self) -> bool {
        (self.bitfield & 0x1) == 0x1
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_new_signature {
    pub next: *mut _gpgme_new_signature,
    pub sig_type: gpgme_sig_mode_t,
    pub pubkey_algo: gpgme_pubkey_algo_t,
    pub hash_algo: gpgme_hash_algo_t,
    _class1: c_ulong,
    pub timestamp: c_long,
    pub fpr: *mut c_char,
    _class2: c_uint,
    pub sig_class: c_uint
}
pub type gpgme_new_signature_t = *mut _gpgme_new_signature;

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_op_sign_result {
    pub invalid_signers: gpgme_invalid_key_t,
    pub signatures: gpgme_new_signature_t
}
pub type gpgme_sign_result_t = *mut _gpgme_op_sign_result;

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_signature {
    pub next: *mut _gpgme_signature,
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
    pub pka_address: *mut c_char
}
pub type gpgme_signature_t = *mut _gpgme_signature;

impl _gpgme_signature {
    pub fn wrong_key_usage(&self) -> bool {
        (self.bitfield & 0x1) == 0x1
    }

    pub fn pka_trust(&self) -> u32 {
        (self.bitfield & 0x6) >> 1
    }

    pub fn chain_model(&self) -> bool {
        (self.bitfield & 0x8) == 0x8
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_op_verify_result {
    pub signatures: gpgme_signature_t,
    pub file_name: *mut c_char
}
pub type gpgme_verify_result_t = *mut _gpgme_op_verify_result;

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_import_status {
    pub next: *mut _gpgme_import_status,
    pub fpr: *mut c_char,
    pub result: gpgme_error_t,
    pub status: c_uint
}
pub type gpgme_import_status_t = *mut _gpgme_import_status;

#[repr(C)]
#[derive(Clone)]
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
    pub imports: gpgme_import_status_t
}
pub type gpgme_import_result_t = *mut _gpgme_op_import_result;

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_op_genkey_result {
    pub bitfield: u32,
    pub fpr: *mut c_char
}
pub type gpgme_genkey_result_t = *mut _gpgme_op_genkey_result;

impl _gpgme_op_genkey_result {
    pub fn primary(&self) -> bool {
        (self.bitfield & 0x1) == 0x1
    }

    pub fn sub(&self) -> bool {
        (self.bitfield & 0x2) == 0x2
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_op_keylist_result {
    pub bitfield: u32
}
pub type gpgme_keylist_result_t = *mut _gpgme_op_keylist_result;

impl _gpgme_op_keylist_result {
    pub fn truncated(&self) -> bool {
        (self.bitfield & 0x1) == 0x1
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_trust_item {
    _refs: c_uint,
    pub keyid: *mut c_char,
    _keyid: [c_char; 17],
    pub trust_type: c_int,
    pub level: c_int,
    pub owner_trust: *mut c_char,
    _owner_trust: [c_char; 2],
    pub validity: *mut c_char,
    _validity: [c_char; 2],
    pub name: *mut c_char
}
pub type gpgme_trust_item_t = *mut _gpgme_trust_item;

pub type gpgme_assuan_data_cb_t = Option<extern fn(*mut c_void, *const c_void, size_t) -> gpgme_error_t>;
pub type gpgme_assuan_inquire_cb_t = Option<extern fn(*mut c_void, *const c_char, *const c_char, *mut gpgme_data_t) -> gpgme_error_t>;
pub type gpgme_assuan_status_cb_t = Option<extern fn(*mut c_void, *const c_char, *const c_char) -> gpgme_error_t>;

#[repr(C)]
#[derive(Clone)]
pub struct _gpgme_op_vfs_mount_result {
    pub mount_dir: *mut c_char
}
pub type gpgme_vfs_mount_result_t = *mut _gpgme_op_vfs_mount_result;

#[repr(C)]
#[derive(Clone)]
pub struct gpgme_conf_arg {
    pub next: *mut gpgme_conf_arg,
    pub no_arg: c_uint,
    pub union: libc::uintptr_t
}
pub type gpgme_conf_arg_t = *mut gpgme_conf_arg;

#[repr(C)]
#[derive(Clone)]
pub struct gpgme_conf_opt {
    pub next: *mut gpgme_conf_opt,
    pub name: *mut c_char,
    pub flags: c_uint,
    pub level: gpgme_conf_level_t,
    pub description: *mut c_char,
    pub opt_type: gpgme_conf_type_t,
    pub alt_type: gpgme_conf_type_t,
    pub argname: *mut c_char,
    pub default_value: gpgme_conf_arg_t,
    pub default_description: *mut c_char,
    pub no_arg_value: gpgme_conf_arg_t,
    pub no_arg_description: *mut c_char,
    pub value: gpgme_conf_arg_t,
    pub change_value: c_int,
    pub new_value: gpgme_conf_arg_t,
    pub user_data: *mut c_void
}
pub type gpgme_conf_opt_t = *mut gpgme_conf_opt;

#[repr(C)]
#[derive(Clone)]
pub struct gpgme_conf_comp {
    pub next: *mut gpgme_conf_comp,
    _last_opt_p: *mut gpgme_conf_opt_t,
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub program_name: *mut c_char,
    pub options: gpgme_conf_opt_t
}
pub type gpgme_conf_comp_t = *mut gpgme_conf_comp;
