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
                        eprintln!("Compile using i586/686 target.");
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
    let root = PathBuf::from(
        key.get_value::<String, _>("Install Directory")
            .warn_err("unable to retrieve install location")?,
    );
    println!("detected install via registry: {}", root.display());
    if root.join("lib/libgpgme.imp").exists() {
        fs::copy(
            root.join("lib/libgpgme.imp"),
            build::out_dir().join("libgpgme.a"),
        )
        .warn_err("unable to rename library")?;
    }

    build::rustc_link_search(build::out_dir());
    build::rustc_link_lib("gpgme");
    true
}
