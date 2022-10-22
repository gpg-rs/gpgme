use gpgme::{Context, Error, PinentryMode};

#[macro_use]
mod common;

test_case! {
    test_pinentry_mode(test) {
        let mode = PinentryMode::Loopback;
        let mut ctx = test.create_context();
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
}
