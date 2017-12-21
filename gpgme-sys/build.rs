extern crate cc;
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
    let path = get_env("GPGME_LIB_DIR");
    let libs = get_env("GPGME_LIBS");
    if path.is_some() || libs.is_some() {
        let mode = match get_env("GPGME_STATIC") {
            Some(_) => "static=",
            _ => "",
        };
        if let Some(v) = get_env("GPGME_VERSION").as_ref().and_then(|s| s.to_str()) {
            print_version(Version::parse(&v).or(Err(()))?);
        }
        for path in path.iter().flat_map(env::split_paths) {
            println!("cargo:rustc-link-search=native={}", path.display());
        }
        for lib in env::split_paths(libs.as_ref().map(|s| &**s).unwrap_or("gpgme".as_ref())) {
            println!("cargo:rustc-link-lib={}{}", mode, lib.display());
        }
        return Ok(());
    }

    if let Some(path) = get_env("GPGME_CONFIG") {
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
    parse_linker_flags(&output(Command::new("sh").arg("-c").arg(cmd))?);
    print_version(version);
    Ok(())
}

fn try_build() -> Result<()> {
    if target().contains("msvc") {
        return Err(());
    }

    let gpgerror_root = PathBuf::from(env::var_os("DEP_GPG_ERROR_ROOT").ok_or(())?);
    let config = Config::new("libassuan")?;
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
    if target().contains("windows") {
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
        "cargo:rustc-link-search={}",
        config.dst.join("lib").display()
    );
    parse_libtool_file(config.dst.join("lib/libgpgme.la"))?;
    println!("cargo:root={}", config.dst.display());
    print_version(Version::parse(INCLUDED_VERSION).unwrap());
    Ok(())
}
