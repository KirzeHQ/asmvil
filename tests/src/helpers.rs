use crate::ffi::{
    sha256_final, sha256_init, sha256_update, sha384_init, sha512_final, sha512_init, sha512_update,
};

pub(crate) fn eq(got: &[u8], want: &[u8]) {
    assert_eq!(got, want);
}

#[repr(align(16))]
pub(crate) struct Context(pub(crate) [u8; 512]);
impl Context {
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }
}
pub(crate) fn ctx(_n: usize) -> Box<Context> {
    Box::new(Context([0; 512]))
}

pub(crate) fn digest256(p: &[u8], chunks: &[usize]) -> Vec<u8> {
    let mut c = ctx(112);
    let mut d = [0; 32];
    unsafe {
        sha256_init(c.as_mut_ptr());
        let mut at = 0;
        for &n in chunks {
            sha256_update(c.as_mut_ptr(), p[at..at + n].as_ptr(), n);
            at += n;
        }
        sha256_final(c.as_mut_ptr(), d.as_mut_ptr());
    }
    d.to_vec()
}

pub(crate) fn digest512(p: &[u8], chunks: &[usize], short: bool) -> Vec<u8> {
    let mut c = ctx(216);
    let mut d = [0; 64];
    unsafe {
        if short {
            sha384_init(c.as_mut_ptr())
        } else {
            sha512_init(c.as_mut_ptr())
        };
        let mut at = 0;
        for &n in chunks {
            sha512_update(c.as_mut_ptr(), p[at..at + n].as_ptr(), n);
            at += n;
        }
        sha512_final(c.as_mut_ptr(), d.as_mut_ptr());
    }
    d[..if short { 48 } else { 64 }].to_vec()
}
