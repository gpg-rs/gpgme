extern crate gcc;
extern crate semver;

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::str;

use semver::Version;

mod build_helper;

use build_helper::*;

const INCLUDED_VERSION: &str = "1.9.0";

fn main() {
    if let Err(_) = configure() {
        process::exit(1);
    }
}

fn configure() -> Result<()> {
    println!("cargo:rerun-if-env-changed=GPGME_LIB_DIR");
    let path = env::var_os("GPGME_LIB_DIR");
    println!("cargo:rerun-if-env-changed=GPGME_LIBS");
    let libs = env::var_os("GPGME_LIBS");
    if path.is_some() || libs.is_some() {
        println!("cargo:rerun-if-env-changed=GPGME_STATIC");
        let mode = match env::var_os("GPGME_STATIC") {
            Some(_) => "static",
            _ => "dylib",
        };
        println!("cargo:rerun-if-env-changed=GPGME_VERSION");
        if let Ok(v) = env::var("GPGME_VERSION") {
            print_version(Version::parse(&v).or(Err(()))?);
        }
        for path in path.iter().flat_map(env::split_paths) {
            println!("cargo:rustc-link-search=native={}", path.display());
        }
        for lib in env::split_paths(libs.as_ref().map(|s| &**s).unwrap_or("gpgme".as_ref())) {
            println!("cargo:rustc-link-lib={0}={1}", mode, lib.display());
        }
        return Ok(());
    }

    println!("cargo:rerun-if-env-changed=GPGME_CONFIG");
    if let Some(path) = env::var_os("GPGME_CONFIG") {
        return try_config(path);
    }

    if !Path::new("libassuan/autogen.sh").exists() || !Path::new("gpgme/autogen.sh").exists() {
        let _ = run(Command::new("git").args(&["submodule", "update", "--init"]));
    }
    let _ = run(Command::new("git")
        .current_dir("gpgme")
        .args(&["apply", "../gpgme-remove-doc.patch"]));

    try_build().or_else(|_| try_config("gpgme-config"))
}

fn print_version(v: Version) {
    println!("cargo:version={}", v);
    println!("cargo:version_major={}", v.major);
    println!("cargo:version_minor={}", v.minor);
    println!("cargo:version_patch={}", v.patch);
}

fn try_config<S: Into<OsString>>(path: S) -> Result<()> {
    let path = path.into();
    let mut cmd = path.clone();
    cmd.push(" --version");
    let version = Version::parse(&output(Command::new("sh").arg("-c").arg(cmd))?).or(Err(()))?;

    let mut cmd = path;
    if cfg!(unix) {
        cmd.push(" --thread=pthread");
    }
    cmd.push(" --libs");
    parse_config_output(&output(Command::new("sh").arg("-c").arg(cmd))?);
    print_version(version);
    Ok(())
}

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

fn try_build() -> Result<()> {
    let gpgerror_root = PathBuf::from(env::var("DEP_GPG_ERROR_ROOT").unwrap());
    let config = Config::new("libassuan")?;

    if config.target.contains("msvc") {
        return Err(());
    }

    run(Command::new("sh")
        .current_dir(&config.src)
        .arg("autogen.sh"))?;
    let mut cmd = config.configure()?;
    cmd.arg("--disable-doc");
    cmd.arg({
        let mut s = OsString::from("--with-libgpg-error-prefix=");
        s.push(msys_compatible(&gpgerror_root)?);
        s
    });
    run(cmd)?;
    run(config.make())?;
    run(config.make().arg("install"))?;

    let config = Config::new("gpgme")?;

    run(Command::new("sh")
        .current_dir(&config.src)
        .arg("autogen.sh"))?;
    let mut cmd = config.configure()?;
    cmd.arg("--disable-languages");
    if config.target.contains("windows") {
        cmd.args(&[
            "--disable-gpgsm-test",
            "--disable-gpgconf-test",
            "--disable-g13-test",
        ]);
    }
    cmd.arg({
        let mut s = OsString::from("--with-libgpg-error-prefix=");
        s.push(msys_compatible(&gpgerror_root)?);
        s
    });
    cmd.arg({
        let mut s = OsString::from("--with-libassuan-prefix=");
        s.push(msys_compatible(&config.dst)?);
        s
    });
    run(cmd)?;
    run(config.make())?;
    run(config.make().arg("install"))?;

    println!(
        "cargo:rustc-link-search=native={}",
        config.dst.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=assuan");
    println!("cargo:rustc-link-lib=static=gpgme");
    println!("cargo:root={}", config.dst.display());
    print_version(Version::parse(INCLUDED_VERSION).unwrap());
    Ok(())
}
