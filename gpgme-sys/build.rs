use std::{ffi::OsString, process::Command};

mod build_helper;

use self::build_helper::*;

fn main() -> Result<()> {
    fn configure() -> Result<Config> {
        let proj = Project::default();
        if let r @ Ok(_) = proj.try_env() {
            return r;
        }

        if let Some(path) = get_env(proj.prefix.clone() + "_CONFIG") {
            return try_config(&proj, path);
        }

        try_config(&proj, "gpgme-config")
    }
    let mut config = configure()?;
    if config.version.is_none() {
        config.try_detect_version("gpgme.h", "GPGME_VERSION")?;
    }
    config.write_version_macro("gpgme");
    config.print();
    Ok(())
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
    proj.try_config(Command::new("sh").arg("-c").arg(cmd)).map(|mut cfg| {
        cfg.version = Some(version.trim().into());
        cfg
    })
}
