#![allow(dead_code)]
use std::{
    env, fs,
    io::prelude::*,
    path::Path,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        RwLock,
    },
};

use gpgme::{self, Context, PassphraseRequest, PinentryMode};

macro_rules! count {
    () => {0usize};
    ($_head:tt $($tail:tt)*) => {1usize + count!($($tail)*)};
}

macro_rules! test_case {
    (@impl $name:ident($tester:ident) $body:block) => {
        #[test]
        fn $name() {
            let $tester = TEST_CASE.new_test();
            $body
        }
    };
    (@impl #[requires($version:tt)] $name:ident($tester:ident) $body:block) => {
        test_case!(@impl $name($tester) {
            use gpgme::require_gpgme_ver;
            require_gpgme_ver! {
                $version => {
                    $body
                }
            }
        });
    };
    ($($(#[requires($version:tt)])? $name:ident($tester:ident) $body:block)+) => {
        static TEST_CASE: ::once_cell::sync::Lazy<$crate::common::TestCase>
            = ::once_cell::sync::Lazy::new(|| $crate::common::TestCase::new(count!($($name)+)));
        $(test_case!(@impl $(#[requires($version)])* $name($tester) $body);)+
    };
}

pub fn passphrase_cb(_req: PassphraseRequest<'_>, out: &mut dyn Write) -> gpgme::Result<()> {
    out.write_all(b"abc")?;
    Ok(())
}

fn import_key(key: &[u8]) {
    let gpg = env::var_os("GPG").unwrap_or("gpg".into());
    let mut child = Command::new(&gpg)
        .arg("--no-permission-warning")
        .arg("--passphrase")
        .arg("abc")
        .arg("--import")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(key).unwrap();
    assert!(child.wait().unwrap().success());
}

fn setup_agent(dir: &Path) {
    env::set_var("GNUPGHOME", dir);
    env::set_var("GPG_AGENT_INFO", "");
    let pinentry = Path::new(env!("CARGO_BIN_EXE_pinentry"));
    if !pinentry.exists() {
        panic!("Unable to find pinentry program");
    }

    let conf = dir.join("gpg.conf");
    fs::write(
        conf,
        "ignore-invalid-option allow-weak-key-signatures\n\
         allow-weak-key-signatures\n",
    )
    .unwrap();

    let agent_conf = dir.join("gpg-agent.conf");
    fs::write(
        agent_conf,
        format!(
            "ignore-invalid-option allow-loopback-pinentry\n\
             allow-loopback-pinentry\n\
             ignore-invalid-option pinentry-mode\n\
             pinentry-mode loopback\n\
             pinentry-program {}\n",
            pinentry.to_str().unwrap()
        ),
    )
    .unwrap();
}

pub struct TestCase {
    count: AtomicUsize,
    homedir: RwLock<Option<tempfile::TempDir>>,
}

impl TestCase {
    pub fn new(count: usize) -> TestCase {
        let dir = tempfile::TempDir::new().unwrap();
        setup_agent(dir.path());
        import_key(include_bytes!("./data/pubdemo.asc"));
        import_key(include_bytes!("./data/secdemo.asc"));
        TestCase {
            count: AtomicUsize::new(count),
            homedir: RwLock::new(Some(dir)),
        }
    }

    pub fn new_test(&self) -> Test<'_> {
        Test { parent: self }
    }

    pub fn kill_agent(&self) {
        let socket = {
            let homedir = self.homedir.read().unwrap();
            homedir.as_ref().unwrap().path().join("S.gpg-agent")
        };
        let mut child = match Command::new("gpg-connect-agent")
            .arg("-S")
            .arg(socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(err) => {
                println!("Unable to kill agent: {}", err);
                return;
            }
        };
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(b"KILLAGENT\nBYE\n");
            let _ = stdin.flush();
        }
        if let Err(err) = child.wait() {
            println!("Unable to kill agent: {}", err);
        }
    }

    fn drop(&self) {
        if self.count.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.kill_agent();
            self.homedir.write().unwrap().take();
        }
    }
}

pub struct Test<'a> {
    parent: &'a TestCase,
}

impl Drop for Test<'_> {
    fn drop(&mut self) {
        self.parent.drop();
    }
}

impl Test<'_> {
    pub fn create_context(&self) -> Context {
        let mut ctx = Context::from_protocol(gpgme::Protocol::OpenPgp).unwrap();
        let _ = ctx.set_pinentry_mode(PinentryMode::Loopback);
        ctx
    }
}
