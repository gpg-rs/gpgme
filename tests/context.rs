use gpgme::{Context, Error, PinentryMode};
use sealed_test::prelude::*;

#[macro_use]
mod common;

#[sealed_test(before = common::setup(), after = common::teardown())]
fn test_pinentry_mode() {
    let mode = PinentryMode::Loopback;
    let mut ctx = common::create_context();
    match ctx.set_pinentry_mode(mode) {
        Ok(()) => {
            // NOTE: UFCS form used here as regression test for
            // issue #17.
            assert_eq!(mode, Context::pinentry_mode(&ctx));
        }
        Err(e) if e.code() == Error::NOT_SUPPORTED.code() => (),
        e @ Err(_) => e.unwrap(),
    }
}
