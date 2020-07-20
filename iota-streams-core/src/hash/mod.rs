use crate::prelude::Vec;

pub trait Hash: Sized {
    /// Hash value size in bytes.
    const HASH_SIZE: usize;

    fn init() -> Self;

    fn update(&mut self, data: &[u8]);

    fn update_bytes(&mut self, data: &Vec<u8>) {
        self.update(&data[..]);
    }

    fn done(&mut self, hash_value: &mut [u8]);

    fn done_bytes(&mut self) -> Vec<u8> {
        let mut hash_value = Vec::with_capacity(Self::HASH_SIZE);
        self.done(&mut hash_value[..]);
        hash_value
    }

    /// Hash data.
    fn hash(data: &[u8], hash_value: &mut [u8]) {
        let mut s = Self::init();
        s.update(data);
        s.done(hash_value);
    }

    /// Hash data.
    fn hash_bytes(data: &Vec<u8>) -> Vec<u8> {
        let mut hash_value = Vec::with_capacity(Self::HASH_SIZE);
        Self::hash(&data[..], &mut hash_value[..]);
        hash_value
    }

    fn rehash(value: &mut [u8]) {
        let mut s = Self::init();
        s.update(value);
        s.done(value);
    }

    fn rehash_bytes(value: &mut Vec<u8>) {
        Self::rehash(&mut value[..]);
    }
}
