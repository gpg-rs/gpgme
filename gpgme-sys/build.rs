#[macro_use]
extern crate cfg_if;
extern crate gcc;

use std::cmp::Ordering;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::iter;
use std::path::{Path, PathBuf};
use std::process::{self, Child, Command, Stdio};
use std::str;

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

fn main() {
    if let Ok(lib) = env::var("GPGME_LIB") {
        let mode = match env::var_os("GPGME_STATIC") {
            Some(_) => "static",
            _ => "dylib",
        };
        println!("cargo:rustc-link-lib={0}={1}", mode, lib);
        return;
    } else if let Some(path) = env::var_os("GPGME_CONFIG") {
        if !try_config(path) {
            process::exit(1);
        }
        return;
    }

    if !Path::new("libassuan/.git").exists() || !Path::new("gpgme/.git").exists() {
        run(Command::new("git").args(&["submodule", "update", "--init"]));
    }

    if try_build() || try_config("gpgme-config") {
        return;
    }
    process::exit(1);
}

fn try_config<S: AsRef<OsStr>>(path: S) -> bool {
    let path = path.as_ref();

    if let Some(output) = output(Command::new(&path).arg("--version")) {
        test_version(&output);
    } else {
        return false;
    }

    if let Some(output) = output(Command::new(&path).arg("--prefix")) {
        println!("cargo:root={}", output);
    }

    let mut command = Command::new(&path);
    if cfg!(unix) {
        command.arg("--thread=pthread");
    }
    command.arg("--libs");
    if let Some(output) = output(&mut command) {
        parse_config_output(&output);
        return true;
    }
    false
}

fn parse_config_output(output: &str) {
    let parts = output.split(|c: char| c.is_whitespace()).filter_map(|p| if p.len() > 2 {
        Some(p.split_at(2))
    } else {
        None
    });

    for (flag, val) in parts {
        match flag {
            "-L" => {
                println!("cargo:rustc-link-search=native={}", val);
            }
            "-F" => {
                println!("cargo:rustc-link-search=framework={}", val);
            }
            "-l" => {
                println!("cargo:rustc-link-lib={}", val);
            }
            _ => {}
        }
    }
}

fn try_build() -> bool {
    let src = PathBuf::from(env::current_dir().unwrap()).join("libassuan");
    let dst = env::var("OUT_DIR").unwrap();
    let build = PathBuf::from(&dst).join("build/assuan");
    let target = env::var("TARGET").unwrap();
    let host = env::var("HOST").unwrap();
    let gpgerror_root = env::var("DEP_GPG_ERROR_ROOT").unwrap();
    let compiler = gcc::Config::new().get_compiler();
    let cflags = compiler.args().iter().fold(OsString::new(), |mut c, a| {
        c.push(a);
        c.push(" ");
        c
    });

    let _ = fs::create_dir_all(&build);

    if !run(Command::new("sh").current_dir(&src).arg("autogen.sh")) {
        return false;
    }
    if !run(Command::new("sh")
        .current_dir(&build)
        .env("CC", compiler.path())
        .env("CFLAGS", &cflags)
        .arg(src.join("configure"))
        .args(&["--enable-maintainer-mode",
                "--build",
                &host, "--host", &target,
                "--enable-static",
                "--disable-shared",
                "--with-pic",
                &format!("--with-libgpg-error-prefix={}", &gpgerror_root),
                &format!("--prefix={}", &dst)])) {
        return false;
    }
    if !run(Command::new("make")
        .current_dir(&build)
        .arg("-j").arg(env::var("NUM_JOBS").unwrap())) {
        return false;
    }
    if !run(Command::new("make")
        .current_dir(&build)
        .arg("install")) {
        return false;
    }

    let src = PathBuf::from(env::current_dir().unwrap()).join("gpgme");
    let build = PathBuf::from(&dst).join("build/gpgme");
    let _ = fs::create_dir_all(&build);

    if !run(Command::new("sh").current_dir(&src).arg("autogen.sh")) {
        return false;
    }
    if !run(Command::new("sh")
        .current_dir(&build)
        .env("CC", compiler.path())
        .env("CFLAGS", &cflags)
        .arg(src.join("configure"))
        .args(&["--enable-maintainer-mode",
                "--build", &host,
                "--host", &target,
                "--enable-static",
                "--disable-shared",
                "--disable-languages",
                "--with-pic",
                &format!("--with-libgpg-error-prefix={}", &gpgerror_root),
                &format!("--with-libassuan-prefix={}", &dst),
                &format!("--prefix={}", &dst)])) {
        return false;
    }
    if !run(Command::new("make")
        .current_dir(&build)
        .arg("-j").arg(env::var("NUM_JOBS").unwrap())) {
        return false;
    }
    if !run(Command::new("make").current_dir(&build).arg("install")) {
        return false;
    }

    println!("cargo:rustc-link-search=native={}",
             PathBuf::from(dst.clone()).join("lib").display());
    println!("cargo:rustc-link-lib=static=assuan");
    println!("cargo:rustc-link-lib=static=gpgme");
    println!("cargo:root={}", &dst);
    true
}

fn test_version(version: &str) {
    let version = version.trim();
    for (x, y) in TARGET_VERSION.split('.').zip(version.split('.').chain(iter::repeat("0"))) {
        let (x, y): (u8, u8) = (x.parse().unwrap(), y.parse().unwrap());
        match x.cmp(&y) {
            Ordering::Less => break,
            Ordering::Greater => {
                panic!("GPGME version `{}` is less than requested `{}`",
                       version,
                       TARGET_VERSION)
            }
            _ => (),
        }
    }
}

fn spawn(cmd: &mut Command) -> Option<Child> {
    println!("running: {:?}", cmd);
    match cmd.stdin(Stdio::null()).spawn() {
        Ok(child) => Some(child),
        Err(e) => {
            println!("failed to execute command: {:?}\nerror: {}", cmd, e);
            None
        }
    }
}

fn run(cmd: &mut Command) -> bool {
    if let Some(mut child) = spawn(cmd) {
        match child.wait() {
            Ok(status) => {
                if !status.success() {
                    println!("command did not execute successfully: {:?}\n\
                       expected success, got: {}", cmd, status);
                } else {
                    return true;
                }
            }
            Err(e) => {
                println!("failed to execute command: {:?}\nerror: {}", cmd, e);
            }
        }
    }
    false
}

fn output(cmd: &mut Command) -> Option<String> {
    if let Some(child) = spawn(cmd.stdout(Stdio::piped())) {
        match child.wait_with_output() {
            Ok(output) => {
                if !output.status.success() {
                    println!("command did not execute successfully: {:?}\n\
                       expected success, got: {}", cmd, output.status);
                } else {
                    return String::from_utf8(output.stdout).ok();
                }
            }
            Err(e) => {
                println!("failed to execute command: {:?}\nerror: {}", cmd, e);
            }
        }
    }
    None
}
