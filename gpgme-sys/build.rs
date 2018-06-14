extern crate cc;

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

mod build_helper;

use build_helper::*;

fn main() {
    Project::default().configure(|proj| {
        if let Ok(mut c) = proj.try_env() {
            let _ = c.try_detect_version("gpgme.h", &(proj.prefix.clone() + "_VERSION"))?;
            return Ok(c);
        }

        if let Some(path) = get_env(proj.prefix.clone() + "_CONFIG") {
            return try_config(&proj, path);
        }

        if let r @ Ok(_) = proj.try_build(build) {
            return r;
        }

        try_config(&proj, "gpgme-config")
    })
}

fn try_config<S: Into<OsString>>(proj: &Project, path: S) -> Result<Config> {
    let path = path.into();
    let mut cmd = path.clone();
    cmd.push(" --version");
    let version = output(Command::new("sh").arg("-c").arg(cmd))?;

    let mut cmd = path;
    cmd.push(" --cflags --libs");
    if cfg!(unix) {
        cmd.push(" --thread=pthread");
    }
    let mut config = proj.try_config(Command::new("sh").arg("-c").arg(cmd))?;
    config.version = Some(version.trim().into());
    Ok(config)
}

fn build(proj: &Project) -> Result<Config> {
    if proj.target.contains("msvc") {
        return Err(());
    }

    let _ = run(Command::new("git")
        .current_dir("gpgme")
        .args(&["apply", "../gpgme-remove-doc.patch"]));

    let gpgerror_root = env::var_os("DEP_GPG_ERROR_ROOT").map(PathBuf::from);
    let build = proj.new_build("libassuan")?;
    run(Command::new("sh").current_dir(&build.src).arg("autogen.sh"))?;
    let mut cmd = build.configure_cmd()?;
    cmd.arg("--disable-doc");
    if let Some(p) = gpgerror_root.as_ref() {
        let mut s = OsString::from("--with-libgpg-error-prefix=");
        s.push(msys_path(&p)?);
        cmd.arg(s);
    }
    run(cmd)?;
    run(build.make_cmd())?;
    run(build.make_cmd().arg("install"))?;

    let build = proj.new_build("gpgme")?;
    run(Command::new("sh").current_dir(&build.src).arg("autogen.sh"))?;
    let mut cmd = build.configure_cmd()?;
    cmd.arg("--disable-languages");
    cmd.arg("--disable-gpg-test");
    if let Some(p) = gpgerror_root.as_ref() {
        let mut s = OsString::from("--with-libgpg-error-prefix=");
        s.push(msys_path(&p)?);
        cmd.arg(s);
    }
    cmd.arg({
        let mut s = OsString::from("--with-libassuan-prefix=");
        s.push(msys_path(&proj.out_dir)?);
        s
    });
    run(cmd)?;
    run(build.make_cmd())?;
    run(build.make_cmd().arg("install"))?;

    let mut config = build.config();
    config.parse_libtool_file(proj.out_dir.join("lib/libgpgme.la"))?;
    config.try_detect_version("gpgme.h", "GPGME_VERSION")?;
    if let Some(p) = gpgerror_root {
        config.include_dir.insert(p.join("include"));
    }
    Ok(config)
}
