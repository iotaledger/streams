use core::convert::AsRef;

use iota_streams_core::prelude::digest::Digest;

use iota_streams_core::prelude::{
    generic_array::GenericArray,
    typenum::U64,
};

#[derive(Default)]
pub(crate) struct Prehashed(pub GenericArray<u8, U64>);

impl Digest for Prehashed {
    type OutputSize = U64;

    fn new() -> Self {
        Self::default()
    }

    fn update(&mut self, _data: impl AsRef<[u8]>) {}

    fn chain(self, _data: impl AsRef<[u8]>) -> Self {
        self
    }

    fn finalize(self) -> GenericArray<u8, Self::OutputSize> {
        self.0
    }

    fn finalize_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        self.0.clone()
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn output_size() -> usize {
        64
    }

    fn digest(_data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        GenericArray::default()
    }
}
