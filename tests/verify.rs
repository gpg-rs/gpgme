#[macro_use]
extern crate lazy_static;

#[macro_use]
mod support;

const TEST_MSG1: &'static [u8] = b"-----BEGIN PGP MESSAGE-----\n\
                                   \n\
                                   owGbwMvMwCSoW1RzPCOz3IRxjXQSR0lqcYleSUWJTZOvjVdpcYmCu1+oQmaJIleH\n\
                                   GwuDIBMDGysTSIqBi1MApi+nlGGuwDeHao53HBr+FoVGP3xX+kvuu9fCMJvl6IOf\n\
                                   y1kvP4y+8D5a11ang0udywsA\n\
                                   =Crq6\n\
                                   -----END PGP MESSAGE-----\n";

test_case! {
    test_signature_key(test) {
        let mut output = Vec::new();
        let mut ctx = test.create_context();
        let result = fail_if_err!(ctx.verify_opaque(TEST_MSG1, &mut output));
        assert_eq!(result.signatures().count(), 1);

        let sig = result.signatures().nth(0).unwrap();
        let key = ctx.get_key(sig.fingerprint_raw().unwrap()).unwrap();
        for subkey in key.subkeys() {
            if subkey.fingerprint_raw() == sig.fingerprint_raw() {
                return;
            }
        }
        assert!(false);
    },
}
