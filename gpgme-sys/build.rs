#[macro_use]
extern crate cfg_if;

use std::cmp::Ordering;
use std::env;
use std::iter;
use std::process::Command;
use std::str;

fn parse_config_output(output: &str) {
    let parts = output.split(|c: char| c.is_whitespace()).filter_map(|p| {
        if p.len() > 2 {
            Some(p.split_at(2))
        } else {
            None
        }
    });

    for (flag, val) in parts {
        match flag {
            "-L" => {
                println!("cargo:rustc-link-search=native={}", val);
            },
            "-F" => {
                println!("cargo:rustc-link-search=framework={}", val);
            },
            "-l" => {
                println!("cargo:rustc-link-lib={}", val);
            },
            _ => {}
        }
    }
}

cfg_if! {
    if #[cfg(feature = "v1_8_0")] {
        const TARGET_VERSION: &'static str = "1.8.0";
    } else if #[cfg(feature = "v1_7_1")] {
        const TARGET_VERSION: &'static str = "1.7.1";
    } else if #[cfg(feature = "v1_7_0")] {
        const TARGET_VERSION: &'static str = "1.7.0";
    } else if #[cfg(feature = "v1_6_0")] {
        const TARGET_VERSION: &'static str = "1.6.0";
    } else if #[cfg(feature = "v1_5_1")] {
        const TARGET_VERSION: &'static str = "1.5.1";
    } else if #[cfg(feature = "v1_5_0")] {
        const TARGET_VERSION: &'static str = "1.5.0";
    } else if #[cfg(feature = "v1_4_3")] {
        const TARGET_VERSION: &'static str = "1.4.3";
    } else if #[cfg(feature = "v1_4_2")] {
        const TARGET_VERSION: &'static str = "1.4.2";
    } else if #[cfg(feature = "v1_4_0")] {
        const TARGET_VERSION: &'static str = "1.4.0";
    } else if #[cfg(feature = "v1_3_1")] {
        const TARGET_VERSION: &'static str = "1.3.1";
    } else if #[cfg(feature = "v1_3_0")] {
        const TARGET_VERSION: &'static str = "1.3.0";
    } else {
        const TARGET_VERSION: &'static str = "1.2.0";
    }
}

fn test_version(version: &str) {
    let version = version.trim();
    for (x, y) in TARGET_VERSION.split('.').zip(version.split('.').chain(
            iter::repeat("0"))) {
        let (x, y): (u8, u8) = (x.parse().unwrap(), y.parse().unwrap());
        match x.cmp(&y) {
            Ordering::Less => break,
            Ordering::Greater => panic!("GPGME version `{}` is less than requested `{}`",
                                        version, TARGET_VERSION),
            _ => (),
        }
    }
}

fn main() {
    if let Ok(lib) = env::var("GPGME_LIB") {
        let mode = match env::var_os("GPGME_STATIC")  {
            Some(_) => "static",
            _ => "dylib",
        };
        println!("cargo:rustc-flags=-l {0}={1}", mode, lib);
    } else {
        let path = env::var_os("GPGME_CONFIG").unwrap_or("gpgme-config".into());
        let mut command = Command::new(&path);
        if cfg!(unix) {
            command.arg("--thread=pthread");
        }
        command.arg("--version");

        let output = command.output().unwrap();
        if !output.status.success() {
            panic!("`{:?}` did not exit successfully: {}", command, output.status);
        }
        test_version(&String::from_utf8(output.stdout).unwrap());

        let mut command = Command::new(&path);
        if cfg!(unix) {
            command.arg("--thread=pthread");
        }
        command.arg("--libs");

        let output = command.output().unwrap();
        if !output.status.success() {
            panic!("`{:?}` did not exit successfully: {}", command, output.status);
        }

        parse_config_output(str::from_utf8(&output.stdout).unwrap());
    }
}

