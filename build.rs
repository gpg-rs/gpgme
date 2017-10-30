extern crate semver;

use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

use semver::Version;

fn main() {
    let (mut major, mut minor) = if let Ok(v) = env::var("DEP_GPGME_VERSION") {
        let sys_version = Version::parse(&v).unwrap();
        (sys_version.major, sys_version.minor)
    } else {
        (0, 0)
    };

    let path = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let mut output = File::create(path.join("version.rs")).unwrap();
    writeln!(
        output,
        "#[macro_export]\nmacro_rules! require_gpgme_ver {{\n\
         ($ver:tt => {{ $($t:tt)* }}) => (require_gpgme_ver! {{ $ver => {{ $($t)* }} else {{}} }});"
    ).unwrap();
    loop {
        writeln!(
            output,
            "(({0},{1}) => {{ $($t:tt)* }} else {{ $($u:tt)* }}) => ($($t)*);",
            major,
            minor
        ).unwrap();

        if minor == 0 {
            break;
        }
        minor -= 1;
    }
    major -= 1;

    loop {
        writeln!(
            output,
            "(({0},$ver:tt) => {{ $($t:tt)* }} else {{ $($u:tt)* }}) => ($($t)*);",
            major
        ).unwrap();

        if major == 0 {
            break;
        }
        major -= 1;
    }
    writeln!(
        output,
        "($ver:tt => {{ $($t:tt)* }} else {{ $($u:tt)* }}) => ($($u)*);\n}}"
    ).unwrap();
}
