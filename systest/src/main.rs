#![allow(bad_style, unused_imports, unused_macros)]
extern crate gpgme_sys;
extern crate libc;

use gpgme_sys::*;
use libc::*;

include!(concat!(env!("OUT_DIR"), "/all.rs"));
