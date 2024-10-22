use sealed_test::prelude::*;

#[macro_use]
mod common;

const TEST_MSG1: &[u8] = b"-----BEGIN PGP MESSAGE-----\n\
                           \n\
                           owGbwMvMwCSoW1RzPCOz3IRxjXQSR0lqcYleSUWJTZOvjVdpcYmCu1+oQmaJIleH\n\
                           GwuDIBMDGysTSIqBi1MApi+nlGGuwDeHao53HBr+FoVGP3xX+kvuu9fCMJvl6IOf\n\
                           y1kvP4y+8D5a11ang0udywsA\n\
                           =Crq6\n\
                           -----END PGP MESSAGE-----\n";

#[sealed_test]
fn test_signature_key() {
    common::with_test_harness(|| {
        let mut ctx = common::create_context();
        let mut output = Vec::new();
        let result = ctx.verify_opaque(TEST_MSG1, &mut output).unwrap();
        assert_eq!(result.signatures().count(), 1);

        let sig = result.signatures().next().unwrap();
        let key = ctx.get_key(sig.fingerprint_raw().unwrap()).unwrap();
        for subkey in key.subkeys() {
            if subkey.fingerprint_raw() == sig.fingerprint_raw() {
                return;
            }
        }
        panic!("verification key not found");
    })
}
