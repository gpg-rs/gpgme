use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    if build::cargo_cfg_windows() && build::cargo_feature("windows_raw_dylib") {
        return Ok(()); // neccessary linker args set in lib.rs
    }

    #[cfg(windows)]
    if try_registry() {
        return Ok(());
    }

    system_deps::Config::new().probe()?;
    Ok(())
}

#[cfg(windows)]
fn try_registry() -> bool {
    use std::{ffi::OsString, path::PathBuf};

    use winreg::{enums::*, RegKey};

    fn try_key(path: &str) -> bool {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let Ok(key) = hklm
            .open_subkey_with_flags(path, KEY_WOW64_32KEY | KEY_READ)
            .inspect_err(|e| eprintln!("unable to retrieve install location: {e}"))
        else {
            return false;
        };
        let Ok(root) = key
            .get_value::<OsString, _>("Install Directory")
            .map(PathBuf::from)
            .inspect_err(|e| eprintln!("unable to retrieve install location: {e}"))
        else {
            return false;
        };

        println!("detected install via registry: {}", root.display());
        build::rustc_link_search(root.join("lib"));
        build::rustc_link_lib("dylib:+verbatim=libgpgme.imp");
        true
    }
    if !build::cargo_cfg_windows() {
        eprintln!("cross compiling. disabling registry detection.");
        return false;
    }

    [r"SOFTWARE\Gpg4win", r"SOFTWARE\GnuPG"]
        .iter()
        .any(|s| try_key(s))
}
