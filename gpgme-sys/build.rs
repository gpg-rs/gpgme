use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(windows)]
    if try_registry() {
        return Ok(());
    }

    system_deps::Config::new().probe()?;
    Ok(())
}

#[cfg(windows)]
fn try_registry() -> bool {
    use std::{ffi::OsString, fs, path::PathBuf};

    use winreg::{enums::*, RegKey};

    if !build::cargo_cfg_windows() {
        eprintln!("cross compiling. disabling registry detection.");
        return false;
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = match hklm.open_subkey_with_flags(r"SOFTWARE\GnuPG", KEY_WOW64_32KEY | KEY_READ) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Unable to retrieve install location: {e}");
            return false;
        }
    };
    let root = match key
        .get_value::<OsString, _>("Install Directory")
        .map(PathBuf::from)
    {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Unable to retrieve install location: {e}");
            return false;
        }
    };
    println!("detected install via registry: {}", root.display());

    if root.join("lib/libgpgme.imp").exists() {
        if let Err(e) = fs::copy(
            root.join("lib/libgpgme.imp"),
            build::out_dir().join("libgpgme.a"),
        ) {
            eprintln!("Unable to rename library: {e}");
            return false;
        }
    }

    build::rustc_link_search(build::out_dir());
    build::rustc_link_lib("gpgme");
    true
}
