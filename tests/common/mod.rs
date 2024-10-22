#![allow(dead_code)]
use std::{
    collections::HashMap,
    env,
    ffi::{OsStr, OsString},
    fs,
    io::prelude::*,
    path::{Path, PathBuf},
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

struct TestHarness {
    wd: PathBuf,
    env: HashMap<&'static str, OsString>,
    gpg: OsString,
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        let _ = self.cmd("gpgconf").args(["--kill", "all"]).status();
    }
}

impl TestHarness {
    fn new() -> Self {
        let wd = env::current_dir().unwrap();
        let env = HashMap::from_iter([
            ("GNUPGHOME", wd.as_os_str().to_owned()),
            ("GPG_AGENT_INFO", OsString::new()),
        ]);
        let gpg = env::var_os("GPG").unwrap_or("gpg".into());
        Self { wd, env, gpg }
    }

    fn cmd(&self, program: impl AsRef<OsStr>) -> Command {
        let mut cmd = Command::new(program);
        cmd.envs(&self.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd
    }

    fn setup_agent(&self) {
        let pinentry = Path::new(env!("CARGO_BIN_EXE_pinentry"));
        if !pinentry.exists() {
            panic!("Unable to find pinentry program");
        }

        let conf = self.wd.join("gpg.conf");
        fs::write(conf, include_str!("./data/gpg.conf")).unwrap();

        let agent_conf = self.wd.join("gpg-agent.conf");
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

    fn import_key(&self, key: &[u8]) {
        let mut child = self
            .cmd(&self.gpg)
            .args([
                "--batch",
                "--no-permission-warning",
                "--passphrase",
                "abc",
                "--import",
            ])
            .spawn()
            .unwrap();
        child.stdin.as_mut().unwrap().write_all(key).unwrap();
        assert!(child.wait().unwrap().success());
    }

    fn import_ownertrust(&self) {
        let mut child = self
            .cmd(&self.gpg)
            .args([
                "--batch",
                "--no-permission-warning",
                "--passphrase",
                "abc",
                "--import",
            ])
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

    fn setup(&self) {
        self.setup_agent();
        self.import_key(include_bytes!("./data/pubdemo.asc"));
        self.import_key(include_bytes!("./data/secdemo.asc"));
        self.import_ownertrust();

        let token = gpgme::init();
        token
            .set_engine_home_dir(
                gpgme::Protocol::OpenPgp,
                self.wd.as_os_str().as_encoded_bytes(),
            )
            .unwrap();
        token
            .check_engine_version(gpgme::Protocol::OpenPgp)
            .unwrap();
    }
}

pub fn with_test_harness(f: impl FnOnce()) {
    let harness = TestHarness::new();
    harness.setup();
    f()
}

pub fn create_context() -> Context {
    let mut ctx = Context::from_protocol(gpgme::Protocol::OpenPgp).unwrap();
    let _ = ctx.set_pinentry_mode(PinentryMode::Loopback);
    ctx
}
