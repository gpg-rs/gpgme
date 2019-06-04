#![allow(non_upper_case_globals, non_camel_case_types)]
#[cfg(not(ctest))]
include!(concat!(env!("OUT_DIR"), "/version.rs"));

pub use self::consts::*;
pub use self::funcs::*;
pub use self::types::*;

mod consts;
mod funcs;
mod types;
