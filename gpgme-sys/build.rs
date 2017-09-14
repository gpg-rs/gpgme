extern crate gcc;
extern crate semver;

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::result;
use std::str;

use semver::Version;

type Result<T> = result::Result<T, ()>;

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
    let _ = run(
        Command::new("git")
            .current_dir("libassuan")
            .args(&["apply", "../libassuan-remove-doc.patch"]),
    );
    let _ = run(
        Command::new("git")
            .current_dir("gpgme")
            .args(&["apply", "../gpgme-remove-doc.patch"]),
    );

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
    let parts = output
        .split(|c: char| c.is_whitespace())
        .filter_map(|p| if p.len() > 2 {
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

fn try_build() -> Result<()> {
    let target = env::var("TARGET").unwrap();
    let host = env::var("HOST").unwrap();
    let src = PathBuf::from(env::current_dir().unwrap()).join("libassuan");
    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let build = dst.join("build/assuan");
    let gpgerror_root = PathBuf::from(env::var("DEP_GPG_ERROR_ROOT").unwrap());
    let compiler = gcc::Build::new().get_compiler();
    let cflags = compiler.args().iter().fold(OsString::new(), |mut c, a| {
        c.push(a);
        c.push(" ");
        c
    });

    if target.contains("msvc") {
        return Err(());
    }

    fs::create_dir_all(&build).map_err(|e| eprintln!("unable to create build directory: {}", e))?;

    run(Command::new("sh").current_dir(&src).arg("autogen.sh"))?;
    run(
        Command::new("sh")
            .current_dir(&build)
            .env("CC", compiler.path())
            .env("CFLAGS", &cflags)
            .arg(msys_compatible(src.join("configure"))?)
            .args(&[
                "--build",
                &gnu_target(&host),
                "--host",
                &gnu_target(&target),
                "--enable-static",
                "--disable-shared",
            ])
            .arg({
                let mut s = OsString::from("--with-libgpg-error-prefix=");
                s.push(msys_compatible(&gpgerror_root)?);
                s
            })
            .arg({
                let mut s = OsString::from("--prefix=");
                s.push(msys_compatible(&dst)?);
                s
            }),
    )?;
    run(make().current_dir(&build))?;
    run(make().current_dir(&build).arg("install"))?;

    let src = src.with_file_name("gpgme");
    let build = build.with_file_name("gpgme");
    let _ = fs::create_dir_all(&build);

    run(Command::new("sh").current_dir(&src).arg("autogen.sh"))?;

    let mut configure = Command::new("sh");
    configure
        .current_dir(&build)
        .env("CC", compiler.path())
        .env("CFLAGS", &cflags)
        .arg(msys_compatible(src.join("configure"))?)
        .args(&[
            "--build",
            &gnu_target(&host),
            "--host",
            &gnu_target(&target),
            "--enable-static",
            "--disable-shared",
            "--disable-languages",
        ])
        .arg({
            let mut s = OsString::from("--with-libgpg-error-prefix=");
            s.push(msys_compatible(&gpgerror_root)?);
            s
        })
        .arg({
            let mut s = OsString::from("--with-libassuan-prefix=");
            s.push(msys_compatible(&dst)?);
            s
        })
        .arg({
            let mut s = OsString::from("--prefix=");
            s.push(msys_compatible(&dst)?);
            s
        });
    if target.contains("windows") {
        configure.args(&[
            "--disable-gpgsm-test",
            "--disable-gpgconf-test",
            "--disable-g13-test",
        ]);
    }
    run(&mut configure)?;
    run(make().current_dir(&build))?;
    run(make().current_dir(&build).arg("install"))?;

    println!(
        "cargo:rustc-link-search=native={}",
        dst.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=assuan");
    println!("cargo:rustc-link-lib=static=gpgme");
    println!("cargo:root={}", dst.display());
    print_version(Version::parse(INCLUDED_VERSION).unwrap());
    Ok(())
}

fn make() -> Command {
    let name = if cfg!(any(target_os = "freebsd", target_os = "dragonfly")) {
        "gmake"
    } else {
        "make"
    };
    let mut cmd = Command::new(name);
    cmd.env_remove("DESTDIR");
    if cfg!(windows) {
        cmd.env_remove("MAKEFLAGS").env_remove("MFLAGS");
    }
    cmd
}

fn msys_compatible<P: AsRef<OsStr>>(path: P) -> Result<OsString> {
    use std::ascii::AsciiExt;

    if !cfg!(windows) {
        return Ok(path.as_ref().to_owned());
    }

    let mut path = path.as_ref()
        .to_str()
        .ok_or_else(|| eprintln!("path is not valid utf-8"))?
        .to_owned();
    if let Some(b'a'...b'z') = path.as_bytes().first().map(u8::to_ascii_lowercase) {
        if path.split_at(1).1.starts_with(":\\") {
            (&mut path[..1]).make_ascii_lowercase();
            path.remove(1);
            path.insert(0, '/');
        }
    }
    Ok(path.replace("\\", "/").into())
}

fn gnu_target(target: &str) -> String {
    match target {
        "i686-pc-windows-gnu" => "i686-w64-mingw32".to_string(),
        "x86_64-pc-windows-gnu" => "x86_64-w64-mingw32".to_string(),
        s => s.to_string(),
    }
}

fn run(cmd: &mut Command) -> Result<String> {
    eprintln!("running: {:?}", cmd);
    match cmd.stdin(Stdio::null())
        .spawn()
        .and_then(|c| c.wait_with_output())
    {
        Ok(output) => if output.status.success() {
            String::from_utf8(output.stdout).or(Err(()))
        } else {
            eprintln!(
                "command did not execute successfully, got: {}",
                output.status
            );
            Err(())
        },
        Err(e) => {
            eprintln!("failed to execute command: {}", e);
            Err(())
        }
    }
}

fn output(cmd: &mut Command) -> Result<String> {
    run(cmd.stdout(Stdio::piped()))
}
