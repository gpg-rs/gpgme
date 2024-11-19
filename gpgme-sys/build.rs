use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    build::rerun_if_changed("build.rs");

    if build::cargo_cfg_windows() && (build::cargo_feature("windows_raw_dylib") || try_registry()) {
        return Ok(());
    }

    system_deps::Config::new().probe()?;
    Ok(())
}

#[cfg(not(windows))]
fn try_registry() -> bool {
    false
}

#[cfg(windows)]
fn try_registry() -> bool {
    use std::{ffi::OsString, path::PathBuf};

    use winreg::{enums::*, RegKey};

    fn try_key(path: &str, wide: bool) -> bool {
        let flags = if wide {
            KEY_WOW64_64KEY
        } else {
            KEY_WOW64_32KEY
        };
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let Ok(key) = hklm.open_subkey_with_flags(path, KEY_READ | flags) else {
            return false;
        };
        let Ok(root) = key
            .get_value::<OsString, _>("Install Directory")
            .map(PathBuf::from)
        else {
            return false;
        };

        match (build::cargo_cfg_pointer_width(), wide) {
            (64, true) | (32, false) => {
                println!("detected install via registry: {}", root.display());
                build::rustc_link_search(root.join("lib"));
                build::rustc_link_lib("dylib:+verbatim=libgpgme.imp");
                true
            }
            _ => {
                eprintln!(
                    "An incompatible installation of GnuPG was detected: {}\n\
                     Try switching the target from 64-bit to 32-bit or 32-bit to 64-bit.\n",
                    root.display()
                );
                false
            }
        }
    }

    [r"SOFTWARE\Gpg4win", r"SOFTWARE\GnuPG"]
        .iter()
        .any(|s| try_key(s, true) || try_key(s, false))
}
