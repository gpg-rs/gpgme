use std::env;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

fn main() -> Result<(), Box<Error>> {
    let (major, minor) = env::var("DEP_GPGME_VERSION")
        .ok()
        .and_then(|v| {
            let mut components = v
                .trim()
                .split('.')
                .scan((), |_, x| x.parse::<u8>().ok())
                .fuse();
            match (components.next(), components.next()) {
                (Some(major), Some(minor)) => Some((major, minor)),
                _ => None,
            }
        })
        .unwrap_or((1, 2));

    let path = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let mut output = File::create(path.join("version.rs"))?;
    writeln!(
        output,
        "pub const MIN_VERSION: &str = \"{}.{}.0\\0\";",
        major, minor
    )?;
    writeln!(
        output,
        "#[macro_export]\nmacro_rules! require_gpgme_ver {{\n\
         ($ver:tt => {{ $($t:tt)* }}) => (require_gpgme_ver! {{ $ver => {{ $($t)* }} else {{}} }});"
    )?;
    for i in 0..=minor {
        writeln!(
            output,
            "(({0},{1}) => {{ $($t:tt)* }} else {{ $($u:tt)* }}) => ($($t)*);",
            major, i
        )?;
    }

    for i in 0..major {
        writeln!(
            output,
            "(({0},$ver:tt) => {{ $($t:tt)* }} else {{ $($u:tt)* }}) => ($($t)*);",
            i
        )?;
    }
    writeln!(
        output,
        "($ver:tt => {{ $($t:tt)* }} else {{ $($u:tt)* }}) => ($($u)*);\n}}"
    )?;
    Ok(())
}
