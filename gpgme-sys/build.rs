use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    if cfg!(windows) && try_registry() {
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
    use std::{fs, path::PathBuf};

    use winreg::{enums::*, RegKey};

    if !build::cargo_cfg_windows() {
        eprintln!("cross compiling. disabling registry detection.");
        return false;
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = match hklm.open_subkey("SOFTWARE\\GnuPG") {
        Ok(k) => k,
        Err(_) => {
            // check if we are on 64bit windows but have 32bit GnuPG installed
            match hklm.open_subkey("SOFTWARE\\WOW6432Node\\GnuPG") {
                Ok(k) => {
                    // found 32bit library
                    if build::cargo_cfg_pointer_width() == 32 {
                        eprintln!("compile using i586/686 target.");
                        return false;
                    } else {
                        k
                    }
                }
                Err(_) => {
                    eprintln!("unable to retrieve install location");
                    return false;
                }
            }
        }
    };
    let root = match key.get_value::<String, _>("Install Directory") {
        Ok(v) => PathBuf::from(v),
        Err(_) => {
            eprintln!("unable to retrieve install location");
            return false;
        }
    };
    println!("detected install via registry: {}", root.display());
    if root.join("lib/libgpg-error.imp").exists() {
        if let Err(e) = fs::copy(
            root.join("lib/libgpg-error.imp"),
            build::out_dir().join("libgpg-error.a"),
        ) {
            eprintln!("unable to rename library: {e}");
            return false;
        }
    }

    build::rustc_link_search(build::out_dir());
    build::rustc_link_lib("gpg-error");
    true
}
