use std::env;
use std::process::Command;
use std::str;

fn parse_config_output(output: &str) {
    let parts: Vec<_> = output.split(' ').filter(|p| p.len() > 2)
        .map(|p| (&p[0..2], &p[2..])).collect();

    for &(flag, val) in parts.iter() {
        match flag {
            "-L" => {
                println!("cargo:rustc-link-search=native={}", val);
            },
            "-F" => {
                println!("cargo:rustc-link-search=framework={}", val);
            },
            "-l" => {
                println!("cargo:rustc-link-lib={}", val);
            },
            _ => {}
        }
    }
}

fn fail<S: AsRef<str>>(s: S) -> ! {
    panic!("\n{}\n\nbuild script failed, exiting...", s.as_ref());
}

fn main() {
    let mut command = Command::new(env::var_os("GPGME_CONFIG").unwrap_or("gpgme-config".into()));
    if cfg!(unix) {
        command.arg("--thread=pthread");
    }
    command.arg("--libs");
    let output = match command.output() {
        Ok(out) => out,
        Err(err) => {
            fail(format!("failed to run `{:?}`: {}", command, err));
        }
    };

    if !output.status.success() {
        fail(format!("`{:?}` did not exit successfully: {}", command, output.status));
    }

    parse_config_output(&str::from_utf8(&output.stdout).unwrap());
}

