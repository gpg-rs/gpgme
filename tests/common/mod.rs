#![allow(dead_code)]
use std::{
    env, fs,
    io::prelude::*,
    path::Path,
    process::{Command, Stdio},
};

use gpgme::{self, Context, PassphraseRequest, PinentryMode};

#[allow(unused_macros)]
macro_rules! assert_matches {
    ($left:expr, $(|)? $($pattern:pat_param)|+ $(if $guard:expr)? $(,)?) => {
        match $left {
            $($pattern)|+ $(if $guard)? => {}
            ref left_val => {
                panic!(r#"assertion `(left matches right)` failed:
                left: `{left_val:?}`
                right: `{}`"#, stringify!($($pattern)|+ $(if $guard)?))
            }
        }
    };
    ($left:expr, $(|)? $( $pattern:pat_param )|+ $( if $guard: expr )?, $($arg:tt)+) => {
        match $left {
            $($pattern)|+ $(if $guard)? => {}
            ref left_val => {
                panic!(r#"assertion `(left matches right)` failed: {}
                left: `{left_val:?}`
                right: `{}`"#, format_args!($($arg)+), stringify!($($pattern)|+ $(if $guard)?))
            }
        }
    };
}

pub fn passphrase_cb(_req: PassphraseRequest<'_>, out: &mut dyn Write) -> gpgme::Result<()> {
    out.write_all(b"abc")?;
    Ok(())
}

fn setup_agent(dir: &Path) {
    env::set_var("GNUPGHOME", dir);
    env::set_var("GPG_AGENT_INFO", "");
    let pinentry = Path::new(env!("CARGO_BIN_EXE_pinentry"));
    if !pinentry.exists() {
        panic!("Unable to find pinentry program");
    }

    let conf = dir.join("gpg.conf");
    fs::write(conf, include_str!("./data/gpg.conf")).unwrap();

    let agent_conf = dir.join("gpg-agent.conf");
    fs::write(
        agent_conf,
        format!(
            concat!(
                include_str!("./data/gpg-agent.conf"),
                "pinentry-program {}\n"
            ),
            pinentry.to_str().unwrap()
        ),
    )
    .unwrap();
}

fn import_key(key: &[u8]) {
    let gpg = env::var_os("GPG").unwrap_or("gpg".into());
    let mut child = Command::new(gpg)
        .args([
            "--batch",
            "--no-permission-warning",
            "--passphrase",
            "abc",
            "--import",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(key).unwrap();
    assert!(child.wait().unwrap().success());
}

fn import_ownertrust() {
    let gpg = env::var_os("GPG").unwrap_or("gpg".into());
    let mut child = Command::new(gpg)
        .args([
            "--batch",
            "--no-permission-warning",
            "--passphrase",
            "abc",
            "--import",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(include_bytes!("./data/ownertrust.txt"))
        .unwrap();
    let _ = child.wait();
}

pub fn setup() {
    let dir = env::current_dir().unwrap();
    setup_agent(&dir);
    import_key(include_bytes!("./data/pubdemo.asc"));
    import_key(include_bytes!("./data/secdemo.asc"));
    import_ownertrust();

    let token = gpgme::init();
    token
        .set_engine_home_dir(gpgme::Protocol::OpenPgp, &*dir.to_string_lossy())
        .unwrap();
    token
        .check_engine_version(gpgme::Protocol::OpenPgp)
        .unwrap();
}

pub fn teardown() {
    let _ = Command::new("gpgconf")
        .args(["--kill", "all"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub fn create_context() -> Context {
    let mut ctx = Context::from_protocol(gpgme::Protocol::OpenPgp).unwrap();
    let _ = ctx.set_pinentry_mode(PinentryMode::Loopback);
    ctx
}
