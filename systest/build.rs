use std::env;

use ctest::TestGenerator;

fn main() {
    let mut cfg = TestGenerator::new();
    if let Some(paths) = env::var_os("DEP_GPGME_INCLUDE") {
        for p in env::split_paths(&paths) {
            cfg.include(p);
        }
    }
    cfg.header("gpgme.h");
    cfg.cfg("ctest", None);

    cfg.skip_struct(|s| match s {
        // Opaque structs
        "gpgme_context" | "gpgme_data" => true,
        _ => false,
    });
    cfg.skip_field(|s, f| match (s, f) {
        ("gpgme_conf_arg", "value") => true,
        (_, "bitfield") => true,
        _ => false,
    });
    cfg.field_name(|_, f| match f {
        "typ" => "type".into(),
        _ => f.into(),
    });

    cfg.generate("../gpgme-sys/lib.rs", "all.rs");
}
