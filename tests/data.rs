use std::io::{prelude::*, SeekFrom};

use gpgme::Data;
use sealed_test::prelude::*;

#[macro_use]
mod common;

type Round = u32;
const TEST_INITIALIZER: Round = 0;
const TEST_INOUT_NONE: Round = 1;
const TEST_INOUT_MEM_NO_COPY: Round = 2;
const TEST_INOUT_MEM_COPY: Round = 3;
const TEST_INOUT_MEM_FROM_FILE_COPY: Round = 4;
const TEST_INOUT_MEM_FROM_INEXISTANT_FILE: Round = 5;
const TEST_INOUT_VEC_NONE: Round = 6;
const TEST_INOUT_VEC: Round = 7;
const TEST_END: Round = 8;

const TEXT: &str = "Just GNU it!\n";
const TEXT2: &str = "Just GNU it!\nJust GNU it!\n";

fn read_once_test(rnd: Round, data: &mut Data) {
    let mut buffer = [0u8; 1024];

    let read = data.read(&mut buffer[..]);
    assert_matches!(read, Ok(1..), "round {rnd:?}");
    assert_eq!(&buffer[..read.unwrap()], TEXT.as_bytes(), "round {rnd:?}");

    let read = data.read(&mut buffer[..]);
    assert_matches!(read, Ok(0), "round {rnd:?}");
}

fn read_test(rnd: Round, data: &mut Data) {
    let mut buffer = [0u8; 1024];
    if matches!(rnd, TEST_INOUT_NONE | TEST_INOUT_VEC_NONE) {
        let read = data.read(&mut buffer);
        assert_matches!(read, Err(_) | Ok(0), "round {rnd:?}");
        return;
    }
    read_once_test(rnd, data);
    data.seek(SeekFrom::Start(0)).unwrap();
    read_once_test(rnd, data);
}

fn write_test(rnd: Round, data: &mut Data) {
    let mut buffer = [0u8; 1024];
    let amt = data.write(TEXT.as_bytes()).unwrap();
    assert_eq!(amt, TEXT.len(), "round {rnd:?}");

    data.seek(SeekFrom::Start(0)).unwrap();
    if matches!(rnd, TEST_INOUT_NONE | TEST_INOUT_VEC_NONE) {
        read_once_test(rnd, data);
    } else {
        let amt = data.read(&mut buffer[..]);
        assert_matches!(amt, Ok(1..), "round {rnd:?}");
        assert_eq!(&buffer[..amt.unwrap()], TEXT2.as_bytes());

        let amt = data.read(&mut buffer[..]);
        assert_matches!(amt, Ok(0), "round {rnd:?}");
    }
}

const MISSING_FILE_NAME: &str = "this-file-surely-does-not-exist";

#[sealed_test(before = common::setup(), after = common::teardown())]
fn test_data() {
    let mut rnd = TEST_INITIALIZER;

    loop {
        rnd += 1;
        let mut data = match rnd {
            TEST_INOUT_NONE => Data::new().unwrap(),
            TEST_INOUT_MEM_NO_COPY => Data::from_buffer(TEXT.as_bytes()).unwrap(),
            TEST_INOUT_MEM_COPY => Data::from_bytes(TEXT.as_bytes()).unwrap(),
            TEST_INOUT_MEM_FROM_FILE_COPY => continue,
            TEST_INOUT_MEM_FROM_INEXISTANT_FILE => {
                let res = Data::load(MISSING_FILE_NAME);
                assert_matches!(res, Err(_), "round {rnd}");
                continue;
            }
            TEST_INOUT_VEC_NONE => Data::try_from(Vec::new()).unwrap(),
            TEST_INOUT_VEC => Data::try_from(TEXT.as_bytes().to_vec()).unwrap(),
            TEST_END => break,
            _ => panic!("unexpected round {rnd}"),
        };

        read_test(rnd, &mut data);
        write_test(rnd, &mut data);
    }
}
