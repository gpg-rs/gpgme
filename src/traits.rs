use error::Result;

pub trait PassphraseCallback: 'static + Send {
    fn read(&mut self, uid_hint: &str, info: &str, prev_was_bad: bool) -> Result<Vec<u8>>;
}

impl<T: 'static + Send> PassphraseCallback for T where T: FnMut(&str, &str, bool) -> Result<Vec<u8>> {
    fn read(&mut self, uid_hint: &str, info: &str, prev_was_bad: bool) -> Result<Vec<u8>> {
        (*self)(uid_hint, info, prev_was_bad)
    }
}

pub trait ProgressCallback: 'static + Send {
    fn report(&mut self, what: &str, typ: isize, current: isize, total: isize);
}

impl<T: 'static + Send> ProgressCallback for T where T: FnMut(&str, isize, isize, isize) {
    fn report(&mut self, what: &str, typ: isize, current: isize, total: isize) {
        (*self)(what, typ, current, total);
    }
}
