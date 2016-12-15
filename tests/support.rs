#![allow(dead_code)]
use std::env;
use std::fs::{self, File};
use std::io;
use std::io::prelude::*;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use tempdir::TempDir;

use gpgme::{self, Context, Data};
use gpgme::PassphraseRequest;

#[macro_export]
macro_rules! fail_if_err {
    ($e:expr) => (match $e {
        Ok(v) => v,
        Err(err) => panic!("Operation failed: {}", err),
    });
}

macro_rules! count {
    () => {0usize};
    ($_head:tt $($tail:tt)*) => {1usize + count!($($tail)*)};
}

macro_rules! test_case {
    (@impl $name:ident($tester:ident) $body:block,) => {
        #[test]
        fn $name() {
            let $tester = TEST_CASE.new_test();
            $body
        }
    };
    (@impl $name:ident($tester:ident) $body:block,
     $($rest_name:ident($rest_tester:ident) $rest_body:block,)+) => {
        test_case!(@impl $name($tester) $body,);
        test_case!(@impl $($rest_name($rest_tester) $rest_body,)+);
    };
    ($($name:ident($tester:ident) $body:block,)+) => {
        lazy_static! {
            static ref TEST_CASE: $crate::support::TestCase =
                $crate::support::TestCase::new(count!($($name)+));
        }
        test_case!(@impl $($name($tester) $body,)+);
    };
    ($($name:ident($tester:ident) $body:block),+) => {
        test_case!($($name($tester) $body,)+);
    };
}

const KEYS: [(&'static str, &'static [u8]); 5] = [("13CD0F3BDF24BE53FE192D62F18737256FF6E4FD",
                                                   include_bytes!("./data/13CD0F3BDF24BE53FE192D62F18737256FF6E4FD")),
                                                  ("76F7E2B35832976B50A27A282D9B87E44577EB66",
                                                   include_bytes!("./data/76F7E2B35832976B50A27A282D9B87E44577EB66")),
                                                  ("A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD",
                                                   include_bytes!("./data/A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD")),
                                                  ("13CBE3758AFE42B5E5E2AE4CED27AFA455E3F87F",
                                                   include_bytes!("./data/13CBE3758AFE42B5E5E2AE4CED27AFA455E3F87F")),
                                                  ("7A030357C0F253A5BBCD282FFC4E521B37558F5C",
                                                   include_bytes!("./data/7A030357C0F253A5BBCD282FFC4E521B37558F5C"))];

pub fn passphrase_cb(_req: PassphraseRequest, out: &mut Write) -> gpgme::Result<()> {
    try!(out.write_all(b"abc"));
    Ok(())
}

fn create_keys(dir: &Path) {
    let keydir = dir.join("private-keys-v1.d");
    fs::create_dir(&keydir).unwrap();
    for &(fpr, key) in &KEYS {
        let mut filename = keydir.join(fpr);
        filename.set_extension("key");
        File::create(filename).unwrap().write_all(key).unwrap();
    }
}

fn import_key(key: &[u8]) {
    let gpg = env::var_os("GPG").unwrap_or("gpg".into());
    let mut child = Command::new(&gpg)
        .arg("--no-permission-warning")
        .arg("--import")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(key).unwrap();
    assert!(child.wait().unwrap().success());
}

pub fn setup_agent(dir: &Path) {
    env::set_var("GNUPGHOME", dir);
    env::set_var("GPG_AGENT_INFO", "");
    let mut pinentry = env::current_exe().unwrap();
    pinentry.pop();
    pinentry.push("pinentry");
    pinentry.set_extension(env::consts::EXE_EXTENSION);

    let agent_conf = dir.join("gpg-agent.conf");
    let mut agent_conf = File::create(agent_conf).unwrap();
    agent_conf.write_all(b"ignore-invalid-option allow-loopback-pinentry\n").unwrap();
    agent_conf.write_all(b"allow-loopback-pinentry\n").unwrap();
    agent_conf.write_all(b"ignore-invalid-option pinentry-mode\n").unwrap();
    agent_conf.write_all(b"pinentry-mode loopback\n").unwrap();
    agent_conf.write_all(b"pinentry-program ").unwrap();
    agent_conf.write_all(pinentry.to_str().unwrap().as_ref()).unwrap();
    agent_conf.write_all(b"\n").unwrap();
}

pub struct TestCase {
    count: AtomicUsize,
    homedir: RwLock<Option<TempDir>>,
}

impl TestCase {
    pub fn new(count: usize) -> TestCase {
        let dir = TempDir::new(".test-gpgme").unwrap();
        setup_agent(dir.path());
        create_keys(dir.path());
        import_key(include_bytes!("./data/pubdemo.asc"));
        import_key(include_bytes!("./data/secdemo.asc"));
        println!("count: {}", count);
        TestCase {
            count: AtomicUsize::new(count),
            homedir: RwLock::new(Some(dir)),
        }
    }

    pub fn new_test(&self) -> Test {
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
            .spawn() {
            Ok(child) => child,
            Err(_) => return,
        };
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(b"KILLAGENT\nBYE\n");
            let _ = stdin.flush();
        }
        let _ = child.wait();
    }

    fn drop(&self) {
        if self.count.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.kill_agent();
            if let Some(dir) = self.homedir.write().unwrap().take() {
                drop(dir);
            }
        }
    }
}

pub struct Test<'a> {
    parent: &'a TestCase,
}

impl<'a> Drop for Test<'a> {
    fn drop(&mut self) {
        self.parent.drop();
    }
}

impl<'a> Test<'a> {
    pub fn create_context(&self) -> Context {
        fail_if_err!(Context::from_protocol(gpgme::Protocol::OpenPgp))
    }

    pub fn check_data(data: &mut Data, expected: &[u8]) {
        let mut buffer = Vec::new();
        data.seek(io::SeekFrom::Start(0)).unwrap();
        data.read_to_end(&mut buffer).unwrap();
        assert_eq!(buffer, expected);
    }
}
