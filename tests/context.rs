extern crate gpgme;
#[macro_use]
extern crate lazy_static;
extern crate tempdir;

use gpgme::Context;
use gpgme::PinentryMode::Loopback;

#[macro_use]
mod support;

test_case! {
    test_pinentry_mode(test) {
        let mode = Loopback;
        let mut context: Context = test.create_context();

        context.set_pinentry_mode(mode).expect("should work");

        let context_ref: &Context = &context;

        assert_eq!(mode, context_ref.pinentry_mode());
    }
}
