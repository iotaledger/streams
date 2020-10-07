use core::hash;

use crate::{
    prelude::Vec,
    sponge::prp::PRP,
};

/// Convenience wrapper for storing Spongos inner state.
// TODO: Use GenericArray for inner buffer.
#[derive(Clone)]
pub struct Inner<F> {
    pub inner: Vec<u8>,
    pub _phantom: core::marker::PhantomData<F>,
}

impl<F> PartialEq for Inner<F> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}
impl<F> Eq for Inner<F> {}

impl<F: PRP> Default for Inner<F> {
    fn default() -> Self {
        Self {
            inner: Vec::with_capacity(F::CAPACITY_BITS / 8),
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<F> hash::Hash for Inner<F> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (self.inner).hash(state);
    }
}

impl<F> AsRef<Vec<u8>> for Inner<F> {
    fn as_ref(&self) -> &Vec<u8> {
        &self.inner
    }
}

impl<F> AsMut<Vec<u8>> for Inner<F> {
    fn as_mut(&mut self) -> &mut Vec<u8> {
        &mut self.inner
    }
}

impl<F> From<Vec<u8>> for Inner<F> {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            inner: bytes,
            _phantom: core::marker::PhantomData,
        }
    }
}
