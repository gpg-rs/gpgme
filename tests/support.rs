use std::env;
use std::fs::{self, File};
use std::io::prelude::*;
use std::path::Path;
use std::process::{Command, Stdio};

use tempdir::TempDir;

use gpgme;

const KEYS: [(&'static str, &'static [u8]); 5] = [
    ("13CD0F3BDF24BE53FE192D62F18737256FF6E4FD",
     include_bytes!("./data/13CD0F3BDF24BE53FE192D62F18737256FF6E4FD")),
    ("76F7E2B35832976B50A27A282D9B87E44577EB66",
     include_bytes!("./data/76F7E2B35832976B50A27A282D9B87E44577EB66")),
    ("A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD",
     include_bytes!("./data/A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD")),
    ("13CBE3758AFE42B5E5E2AE4CED27AFA455E3F87F",
     include_bytes!("./data/13CBE3758AFE42B5E5E2AE4CED27AFA455E3F87F")),
    ("7A030357C0F253A5BBCD282FFC4E521B37558F5C",
     include_bytes!("./data/7A030357C0F253A5BBCD282FFC4E521B37558F5C")),
];

fn create_keys(dir: &Path) {
    let keydir = dir.join("private-keys-v1.d");
    fs::create_dir(&keydir).unwrap();
    for &(fpr, key) in KEYS.iter() {
        let mut filename = keydir.join(fpr);
        filename.set_extension("key");
        File::create(filename).unwrap().write_all(key).unwrap();
    }
}

fn import_key(key: &[u8]) {
    let mut child = Command::new("gpg").arg("--no-permission-warning")
        .arg("--import").stdin(Stdio::piped()).stdout(Stdio::null())
        .stderr(Stdio::null()).spawn().unwrap();
    child.stdin.as_mut().unwrap().write_all(key).unwrap();
    assert!(child.wait().unwrap().success());
}

fn setup_agent(dir: &Path) {
    env::set_var("GNUPGHOME", dir);
    env::set_var("GPG_AGENT_INFO", "");
    let mut source = env::current_exe().unwrap();
    source.pop();
    source.push("pinentry");
    source.set_extension(env::consts::EXE_EXTENSION);
    let pinentry = dir.join("pinentry");
    fs::copy(&source, &pinentry).unwrap();

    let agent_conf = dir.join("gpg-agent.conf");
    let mut agent_conf = File::create(agent_conf).unwrap();
    agent_conf.write_all(b"pinentry-program ").unwrap();
    agent_conf.write_all(pinentry.to_str().unwrap().as_ref()).unwrap();
    agent_conf.write_all(b"\n").unwrap();
}

pub fn setup() -> TempDir {
    let dir = TempDir::new(".test-gpgme").unwrap();
    setup_agent(dir.path());
    create_keys(dir.path());
    import_key(include_bytes!("./data/pubdemo.asc"));
    import_key(include_bytes!("./data/secdemo.asc"));
    dir
}

#[allow(dead_code)]
pub fn passphrase_cb(_hint: &str, _info: &str, _prev_was_bad: bool) -> gpgme::Result<Vec<u8>> {
    Ok(b"abc\n".to_vec())
}
