extern crate libc;

use libc::{c_char, c_int, c_long, c_short, c_uchar, c_uint, c_ulong, c_ushort, c_void, size_t,
           ssize_t};

pub use libgpg_error_sys::gpg_err_make as gpgme_err_make;
pub use libgpg_error_sys::gpg_err_code as gpgme_err_code;
pub use libgpg_error_sys::gpg_err_source as gpgme_err_source;
pub use libgpg_error_sys::gpg_strerror as gpgme_strerror;
pub use libgpg_error_sys::gpg_strerror_r as gpgme_strerror_r;
pub use libgpg_error_sys::gpg_strsource as gpgme_strsource;
pub use libgpg_error_sys::gpg_err_code_from_errno as gpgme_err_code_from_errno;
pub use libgpg_error_sys::gpg_err_code_to_errno as gpgme_err_code_to_errno;
pub use libgpg_error_sys::gpg_err_code_from_syserror as gpgme_err_code_from_syserror;
pub use libgpg_error_sys::gpg_err_set_errno as gpgme_err_set_errno;
pub use libgpg_error_sys::gpg_err_make_from_errno as gpgme_err_make_from_errno;
pub use libgpg_error_sys::gpg_error_from_errno as gpgme_error_from_errno;
pub use libgpg_error_sys::gpg_error_from_syserror as gpgme_error_from_syserror;

use consts::*;
use types::*;

extern "C" {
    pub fn gpgme_set_global_flag(name: *const c_char, value: *const c_char) -> c_int;

    pub fn gpgme_check_version(req_version: *const c_char) -> *const c_char;
    pub fn gpgme_check_version_internal(
        req_version: *const c_char, offset_sig_validity: size_t
    ) -> *const c_char;

    pub fn gpgme_get_dirinfo(what: *const c_char) -> *const c_char;

    pub fn gpgme_get_engine_info(engine_info: *mut gpgme_engine_info_t) -> gpgme_error_t;
    pub fn gpgme_set_engine_info(
        proto: gpgme_protocol_t, file_name: *const c_char, home_dir: *const c_char
    ) -> gpgme_error_t;

    pub fn gpgme_engine_check_version(proto: gpgme_protocol_t) -> gpgme_error_t;

    pub fn gpgme_result_ref(result: *mut c_void);
    pub fn gpgme_result_unref(result: *mut c_void);

    pub fn gpgme_new(ctx: *mut gpgme_ctx_t) -> gpgme_error_t;
    pub fn gpgme_release(ctx: gpgme_ctx_t);

    pub fn gpgme_set_ctx_flag(
        ctx: gpgme_ctx_t, name: *const c_char, value: *const c_char
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
        ctx: gpgme_ctx_t, cb: gpgme_passphrase_cb_t, hook_value: *mut c_void
    );
    pub fn gpgme_get_passphrase_cb(
        ctx: gpgme_ctx_t, cb: *mut gpgme_passphrase_cb_t, hood_value: *mut *mut c_void
    );

    pub fn gpgme_set_progress_cb(
        ctx: gpgme_ctx_t, cb: gpgme_progress_cb_t, hook_value: *mut c_void
    );
    pub fn gpgme_get_progress_cb(
        ctx: gpgme_ctx_t, cb: *mut gpgme_progress_cb_t, hook_value: *mut *mut c_void
    );

    pub fn gpgme_set_status_cb(ctx: gpgme_ctx_t, cb: gpgme_status_cb_t, hook_value: *mut c_void);
    pub fn gpgme_get_status_cb(
        ctx: gpgme_ctx_t, cb: *mut gpgme_status_cb_t, hook_value: *mut *mut c_void
    );

    pub fn gpgme_set_locale(
        ctx: gpgme_ctx_t, category: c_int, value: *const c_char
    ) -> gpgme_error_t;

    pub fn gpgme_ctx_get_engine_info(ctx: gpgme_ctx_t) -> gpgme_engine_info_t;
    pub fn gpgme_ctx_set_engine_info(
        ctx: gpgme_ctx_t, proto: gpgme_protocol_t, file_name: *const c_char,
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
        ctx: gpgme_ctx_t, name: *const c_char, value: *const c_char,
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
        ctx: gpgme_ctx_t, status: *mut gpgme_error_t, op_err: *mut gpgme_error_t, hang: c_int
    ) -> gpgme_ctx_t;

    pub fn gpgme_data_read(dh: gpgme_data_t, buffer: *mut c_void, size: size_t) -> ssize_t;
    pub fn gpgme_data_write(dh: gpgme_data_t, buffer: *const c_void, size: size_t) -> ssize_t;
    pub fn gpgme_data_seek(dh: gpgme_data_t, offset: libc::off_t, whence: c_int) -> libc::off_t;

    pub fn gpgme_data_new(r_dh: *mut gpgme_data_t) -> gpgme_error_t;
    pub fn gpgme_data_release(dh: gpgme_data_t);

    pub fn gpgme_data_new_from_mem(
        r_dh: *mut gpgme_data_t, buffer: *const c_char, size: size_t, copy: c_int
    ) -> gpgme_error_t;
    pub fn gpgme_data_release_and_get_mem(dh: gpgme_data_t, r_len: *mut size_t) -> *mut c_char;
    pub fn gpgme_free(buffer: *mut c_void);

    pub fn gpgme_data_new_from_cbs(
        dh: *mut gpgme_data_t, cbs: gpgme_data_cbs_t, handle: *mut c_void
    ) -> gpgme_error_t;
    pub fn gpgme_data_new_from_fd(dh: *mut gpgme_data_t, fd: c_int) -> gpgme_error_t;

    pub fn gpgme_data_new_from_stream(
        dh: *mut gpgme_data_t, stream: *mut libc::FILE
    ) -> gpgme_error_t;

    pub fn gpgme_data_get_encoding(dh: gpgme_data_t) -> gpgme_data_encoding_t;
    pub fn gpgme_data_set_encoding(dh: gpgme_data_t, enc: gpgme_data_encoding_t) -> gpgme_error_t;

    pub fn gpgme_data_get_file_name(dh: gpgme_data_t) -> *mut c_char;
    pub fn gpgme_data_set_file_name(dh: gpgme_data_t, file_name: *const c_char) -> gpgme_error_t;

    pub fn gpgme_data_set_flag(
        dh: gpgme_data_t, name: *const c_char, value: *const c_char
    ) -> gpgme_error_t;

    pub fn gpgme_data_identify(dh: gpgme_data_t, _reserved: c_int) -> gpgme_data_type_t;

    pub fn gpgme_data_new_from_file(
        r_dh: *mut gpgme_data_t, fname: *const c_char, copy: c_int
    ) -> gpgme_error_t;
    pub fn gpgme_data_new_from_filepart(
        r_dh: *mut gpgme_data_t, fname: *const c_char, fp: *mut libc::FILE, offset: libc::off_t,
        length: size_t,
    ) -> gpgme_error_t;

    pub fn gpgme_get_key(
        ctx: gpgme_ctx_t, fpr: *const c_char, r_key: *mut gpgme_key_t, secret: c_int
    ) -> gpgme_error_t;
    pub fn gpgme_key_ref(key: gpgme_key_t);
    pub fn gpgme_key_unref(key: gpgme_key_t);
    pub fn gpgme_key_release(key: gpgme_key_t);

    pub fn gpgme_cancel(ctx: gpgme_ctx_t) -> gpgme_error_t;
    pub fn gpgme_cancel_async(ctx: gpgme_ctx_t) -> gpgme_error_t;

    pub fn gpgme_op_encrypt_result(ctx: gpgme_ctx_t) -> gpgme_encrypt_result_t;
    pub fn gpgme_op_encrypt_start(
        ctx: gpgme_ctx_t, recp: *mut gpgme_key_t, flags: gpgme_encrypt_flags_t,
        plain: gpgme_data_t, cipher: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_encrypt(
        ctx: gpgme_ctx_t, recp: *mut gpgme_key_t, flags: gpgme_encrypt_flags_t,
        plain: gpgme_data_t, cipher: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_encrypt_sign_start(
        ctx: gpgme_ctx_t, recp: *mut gpgme_key_t, flags: gpgme_encrypt_flags_t,
        plain: gpgme_data_t, cipher: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_encrypt_sign(
        ctx: gpgme_ctx_t, recp: *mut gpgme_key_t, flags: gpgme_encrypt_flags_t,
        plain: gpgme_data_t, cipher: gpgme_data_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_decrypt_result(ctx: gpgme_ctx_t) -> gpgme_decrypt_result_t;
    pub fn gpgme_op_decrypt_start(
        ctx: gpgme_ctx_t, cipher: gpgme_data_t, plain: gpgme_data_t
    ) -> gpgme_error_t;
    pub fn gpgme_op_decrypt(
        ctx: gpgme_ctx_t, cipher: gpgme_data_t, plain: gpgme_data_t
    ) -> gpgme_error_t;
    pub fn gpgme_op_decrypt_verify_start(
        ctx: gpgme_ctx_t, cipher: gpgme_data_t, plain: gpgme_data_t
    ) -> gpgme_error_t;
    pub fn gpgme_op_decrypt_verify(
        ctx: gpgme_ctx_t, cipher: gpgme_data_t, plain: gpgme_data_t
    ) -> gpgme_error_t;
    pub fn gpgme_op_decrypt_ext_start(
        ctx: gpgme_ctx_t, flags: gpgme_decrypt_flags_t, cipher: gpgme_data_t, plain: gpgme_data_t
    ) -> gpgme_error_t;
    pub fn gpgme_op_decrypt_ext(
        ctx: gpgme_ctx_t, flags: gpgme_decrypt_flags_t, cipher: gpgme_data_t, plain: gpgme_data_t
    ) -> gpgme_error_t;

    pub fn gpgme_op_sign_result(ctx: gpgme_ctx_t) -> gpgme_sign_result_t;
    pub fn gpgme_op_sign_start(
        ctx: gpgme_ctx_t, plain: gpgme_data_t, sig: gpgme_data_t, mode: gpgme_sig_mode_t
    ) -> gpgme_error_t;
    pub fn gpgme_op_sign(
        ctx: gpgme_ctx_t, plain: gpgme_data_t, sig: gpgme_data_t, mode: gpgme_sig_mode_t
    ) -> gpgme_error_t;

    pub fn gpgme_op_verify_result(ctx: gpgme_ctx_t) -> gpgme_verify_result_t;
    pub fn gpgme_op_verify_start(
        ctx: gpgme_ctx_t, sig: gpgme_data_t, signed_text: gpgme_data_t, plaintext: gpgme_data_t
    ) -> gpgme_error_t;
    pub fn gpgme_op_verify(
        ctx: gpgme_ctx_t, sig: gpgme_data_t, signed_text: gpgme_data_t, plaintext: gpgme_data_t
    ) -> gpgme_error_t;

    pub fn gpgme_op_import_result(ctx: gpgme_ctx_t) -> gpgme_import_result_t;
    pub fn gpgme_op_import_start(ctx: gpgme_ctx_t, keydata: gpgme_data_t) -> gpgme_error_t;
    pub fn gpgme_op_import(ctx: gpgme_ctx_t, keydata: gpgme_data_t) -> gpgme_error_t;

    pub fn gpgme_op_import_keys_start(ctx: gpgme_ctx_t, keys: *mut gpgme_key_t) -> gpgme_error_t;
    pub fn gpgme_op_import_keys(ctx: gpgme_ctx_t, keys: *mut gpgme_key_t) -> gpgme_error_t;

    pub fn gpgme_op_export_start(
        ctx: gpgme_ctx_t, pattern: *const c_char, mode: gpgme_export_mode_t, keydata: gpgme_data_t
    ) -> gpgme_error_t;
    pub fn gpgme_op_export(
        ctx: gpgme_ctx_t, pattern: *const c_char, mode: gpgme_export_mode_t, keydata: gpgme_data_t
    ) -> gpgme_error_t;

    pub fn gpgme_op_export_ext_start(
        ctx: gpgme_ctx_t, pattern: *mut *const c_char, mode: gpgme_export_mode_t,
        keydata: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_export_ext(
        ctx: gpgme_ctx_t, pattern: *mut *const c_char, mode: gpgme_export_mode_t,
        keydata: gpgme_data_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_export_keys_start(
        ctx: gpgme_ctx_t, keys: *mut gpgme_key_t, mode: gpgme_export_mode_t, keydata: gpgme_data_t
    ) -> gpgme_error_t;
    pub fn gpgme_op_export_keys(
        ctx: gpgme_ctx_t, keys: *mut gpgme_key_t, mode: gpgme_export_mode_t, keydata: gpgme_data_t
    ) -> gpgme_error_t;

    pub fn gpgme_op_genkey_result(ctx: gpgme_ctx_t) -> gpgme_genkey_result_t;
    pub fn gpgme_op_genkey_start(
        ctx: gpgme_ctx_t, parms: *const c_char, pubkey: gpgme_data_t, seckey: gpgme_data_t
    ) -> gpgme_error_t;
    pub fn gpgme_op_genkey(
        ctx: gpgme_ctx_t, parms: *const c_char, pubkey: gpgme_data_t, seckey: gpgme_data_t
    ) -> gpgme_error_t;
    pub fn gpgme_op_createkey_start(
        ctx: gpgme_ctx_t, userid: *const c_char, algo: *const c_char, reserved: c_ulong,
        expires: c_ulong, certkey: gpgme_key_t, flags: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_createkey(
        ctx: gpgme_ctx_t, userid: *const c_char, algo: *const c_char, reserved: c_ulong,
        expires: c_ulong, certkey: gpgme_key_t, flags: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_createsubkey_start(
        ctx: gpgme_ctx_t, key: gpgme_key_t, algo: *const c_char, reserved: c_ulong,
        expires: c_ulong, flags: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_createsubkey(
        ctx: gpgme_ctx_t, key: gpgme_key_t, algo: *const c_char, reserved: c_ulong,
        expires: c_ulong, flags: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_adduid_start(
        ctx: gpgme_ctx_t, key: gpgme_key_t, userid: *const c_char, reserved: c_uint
    ) -> gpgme_error_t;
    pub fn gpgme_op_adduid(
        ctx: gpgme_ctx_t, key: gpgme_key_t, userid: *const c_char, reserved: c_uint
    ) -> gpgme_error_t;
    pub fn gpgme_op_revuid_start(
        ctx: gpgme_ctx_t, key: gpgme_key_t, userid: *const c_char, reserved: c_uint
    ) -> gpgme_error_t;
    pub fn gpgme_op_revuid(
        ctx: gpgme_ctx_t, key: gpgme_key_t, userid: *const c_char, reserved: c_uint
    ) -> gpgme_error_t;
    pub fn gpgme_op_set_uid_flag_start(
        ctx: gpgme_ctx_t, key: gpgme_key_t, userid: *const c_char, name: *const c_char,
        value: *const c_char,
    ) -> gpgme_error_t;
    pub fn gpgme_op_set_uid_flag(
        ctx: gpgme_ctx_t, key: gpgme_key_t, userid: *const c_char, name: *const c_char,
        value: *const c_char,
    ) -> gpgme_error_t;

    pub fn gpgme_op_delete_start(
        ctx: gpgme_ctx_t, key: gpgme_key_t, allow_secret: c_int
    ) -> gpgme_error_t;
    pub fn gpgme_op_delete(
        ctx: gpgme_ctx_t, key: gpgme_key_t, allow_secret: c_int
    ) -> gpgme_error_t;

    pub fn gpgme_op_keysign_start(
        ctx: gpgme_ctx_t, key: gpgme_key_t, userid: *const c_char, expires: c_ulong, flags: c_uint
    ) -> gpgme_error_t;
    pub fn gpgme_op_keysign(
        ctx: gpgme_ctx_t, key: gpgme_key_t, userid: *const c_char, expires: c_ulong, flags: c_uint
    ) -> gpgme_error_t;

    pub fn gpgme_op_interact_start(
        ctx: gpgme_ctx_t, key: gpgme_key_t, flags: c_uint, fnc: gpgme_interact_cb_t,
        fnc_value: *mut c_void, out: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_interact(
        ctx: gpgme_ctx_t, key: gpgme_key_t, flags: c_uint, fnc: gpgme_interact_cb_t,
        fnc_value: *mut c_void, out: gpgme_data_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_edit_start(
        ctx: gpgme_ctx_t, key: gpgme_key_t, fnc: gpgme_edit_cb_t, fnc_value: *mut c_void,
        out: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_edit(
        ctx: gpgme_ctx_t, key: gpgme_key_t, fnc: gpgme_edit_cb_t, fnc_value: *mut c_void,
        out: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_card_edit_start(
        ctx: gpgme_ctx_t, key: gpgme_key_t, fnc: gpgme_edit_cb_t, fnc_value: *mut c_void,
        out: gpgme_data_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_card_edit(
        ctx: gpgme_ctx_t, key: gpgme_key_t, fnc: gpgme_edit_cb_t, fnc_value: *mut c_void,
        out: gpgme_data_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_tofu_policy_start(
        ctx: gpgme_ctx_t, key: gpgme_key_t, policy: gpgme_tofu_policy_t
    ) -> gpgme_error_t;
    pub fn gpgme_op_tofu_policy(
        ctx: gpgme_ctx_t, key: gpgme_key_t, policy: gpgme_tofu_policy_t
    ) -> gpgme_error_t;

    pub fn gpgme_op_spawn_start(
        ctx: gpgme_ctx_t, file: *const c_char, argv: *mut *const c_char, datain: gpgme_data_t,
        dataout: gpgme_data_t, dataerr: gpgme_data_t, flags: c_uint,
    ) -> gpgme_error_t;
    pub fn gpgme_op_spawn(
        ctx: gpgme_ctx_t, file: *const c_char, argv: *mut *const c_char, datain: gpgme_data_t,
        dataout: gpgme_data_t, dataerr: gpgme_data_t, flags: c_uint,
    ) -> gpgme_error_t;

    pub fn gpgme_op_keylist_result(ctx: gpgme_ctx_t) -> gpgme_keylist_result_t;
    pub fn gpgme_op_keylist_start(
        ctx: gpgme_ctx_t, pattern: *const c_char, secret_only: c_int
    ) -> gpgme_error_t;
    pub fn gpgme_op_keylist_ext_start(
        ctx: gpgme_ctx_t, pattern: *mut *const c_char, secret_only: c_int, _reserved: c_int
    ) -> gpgme_error_t;
    pub fn gpgme_op_keylist_from_data_start(
        ctx: gpgme_ctx_t, data: gpgme_data_t, reserved: c_int
    ) -> gpgme_error_t;
    pub fn gpgme_op_keylist_next(ctx: gpgme_ctx_t, r_key: *mut gpgme_key_t) -> gpgme_error_t;
    pub fn gpgme_op_keylist_end(ctx: gpgme_ctx_t) -> gpgme_error_t;

    pub fn gpgme_op_passwd_start(
        ctx: gpgme_ctx_t, key: gpgme_key_t, flags: c_uint
    ) -> gpgme_error_t;
    pub fn gpgme_op_passwd(ctx: gpgme_ctx_t, key: gpgme_key_t, flags: c_uint) -> gpgme_error_t;

    pub fn gpgme_op_trustlist_start(
        ctx: gpgme_ctx_t, pattern: *const c_char, max_level: c_int
    ) -> gpgme_error_t;
    pub fn gpgme_op_trustlist_next(
        ctx: gpgme_ctx_t, r_item: *mut gpgme_trust_item_t
    ) -> gpgme_error_t;
    pub fn gpgme_op_trustlist_end(ctx: gpgme_ctx_t) -> gpgme_error_t;

    pub fn gpgme_trust_item_ref(item: gpgme_trust_item_t);
    pub fn gpgme_trust_item_unref(item: gpgme_trust_item_t);

    pub fn gpgme_op_getauditlog_start(
        ctx: gpgme_ctx_t, output: gpgme_data_t, flags: c_uint
    ) -> gpgme_error_t;
    pub fn gpgme_op_getauditlog(
        ctx: gpgme_ctx_t, output: gpgme_data_t, flags: c_uint
    ) -> gpgme_error_t;

    pub fn gpgme_op_assuan_transact_start(
        ctx: gpgme_ctx_t, command: *const c_char, data_cb: gpgme_assuan_data_cb_t,
        data_cb_value: *mut c_void, inq_cb: gpgme_assuan_inquire_cb_t, inq_cb_value: *mut c_void,
        stat_cb: gpgme_assuan_status_cb_t, stat_cb_value: *mut c_void,
    ) -> gpgme_error_t;
    pub fn gpgme_op_assuan_transact_ext(
        ctx: gpgme_ctx_t, command: *const c_char, data_cb: gpgme_assuan_data_cb_t,
        data_cb_value: *mut c_void, inq_cb: gpgme_assuan_inquire_cb_t, inq_cb_value: *mut c_void,
        stat_cb: gpgme_assuan_status_cb_t, stat_cb_value: *mut c_void, op_err: *mut gpgme_error_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_vfs_mount_result(ctx: gpgme_ctx_t) -> gpgme_vfs_mount_result_t;
    pub fn gpgme_op_vfs_mount(
        ctx: gpgme_ctx_t, container_file: *const c_char, mount_dir: *const c_char, flags: c_uint,
        op_err: *mut gpgme_error_t,
    ) -> gpgme_error_t;
    pub fn gpgme_op_vfs_create(
        ctx: gpgme_ctx_t, recp: *mut gpgme_key_t, container_file: *const c_char, flags: c_uint,
        op_err: *mut gpgme_error_t,
    ) -> gpgme_error_t;

    pub fn gpgme_op_query_swdb(
        ctx: gpgme_ctx_t, name: *const c_char, iversion: *const c_char, _reserved: c_uint
    ) -> gpgme_error_t;
    pub fn gpgme_op_query_swdb_result(ctx: gpgme_ctx_t) -> gpgme_query_swdb_result_t;

    pub fn gpgme_conf_arg_new(
        arg_p: *mut gpgme_conf_arg_t, arg_type: gpgme_conf_type_t, value: *const c_void
    ) -> gpgme_error_t;
    pub fn gpgme_conf_arg_release(arg: gpgme_conf_arg_t, arg_type: gpgme_conf_type_t);
    pub fn gpgme_conf_opt_change(
        opt: gpgme_conf_opt_t, reset: c_int, arg: gpgme_conf_arg_t
    ) -> gpgme_error_t;
    pub fn gpgme_conf_release(conf: gpgme_conf_comp_t);

    pub fn gpgme_op_conf_load(ctx: gpgme_ctx_t, conf_p: *mut gpgme_conf_comp_t) -> gpgme_error_t;
    pub fn gpgme_op_conf_save(ctx: gpgme_ctx_t, comp: gpgme_conf_comp_t) -> gpgme_error_t;

    pub fn gpgme_key_from_uid(key: *mut gpgme_key_t, name: *const c_char) -> gpgme_error_t;
}
