use bytes::{Buf, BufMut};

pub(crate) fn peek_u8<B: Buf>(b: &B) -> Option<u8> {
    b.chunk().get(0).copied()
}

pub(crate) fn get_ssh_string<B: Buf>(mut b: B) -> Vec<u8> {
    let len = b.get_u32();
    let mut s = vec![0u8; len as usize];
    b.copy_to_slice(&mut s[..]);
    s
}

pub(crate) fn put_ssh_string<B: BufMut>(mut b: B, s: &[u8]) {
    let len = s.len() as u32;
    b.put_u32(len);
    b.put_slice(s);
}
