use core::hash;

use crate::{
    prelude::generic_array::GenericArray,
    sponge::prp::PRP,
};

/// Convenience wrapper for storing Spongos inner state.
#[derive(Clone)]
pub struct Inner<F: PRP> {
    /// Represents inner state of spongos automaton.
    inner: GenericArray<u8, F::CapacitySize>,
    /// Keep info about PRP.
    _phantom: core::marker::PhantomData<F>,
}

impl<F: PRP> Inner<F> {
    pub fn arr(&self) -> &GenericArray<u8, F::CapacitySize> {
        &self.inner
    }

    pub fn arr_mut(&mut self) -> &mut GenericArray<u8, F::CapacitySize> {
        &mut self.inner
    }
}

impl<F: PRP> PartialEq for Inner<F> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}
impl<F: PRP> Eq for Inner<F> {}

impl<F: PRP> Default for Inner<F> {
    fn default() -> Self {
        Self {
            inner: GenericArray::default(),
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<F: PRP> hash::Hash for Inner<F> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (self.inner).hash(state);
    }
}

impl<F: PRP> AsRef<[u8]> for Inner<F> {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl<F: PRP> AsMut<[u8]> for Inner<F> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.inner.as_mut()
    }
}

impl<F: PRP> From<GenericArray<u8, F::CapacitySize>> for Inner<F> {
    fn from(bytes: GenericArray<u8, F::CapacitySize>) -> Self {
        Self {
            inner: bytes,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<F: PRP> From<Inner<F>> for GenericArray<u8, F::CapacitySize> {
    fn from(inner: Inner<F>) -> Self {
        inner.inner
    }
}

impl<'a, F: PRP> From<&'a Inner<F>> for &'a GenericArray<u8, F::CapacitySize> {
    fn from(inner: &'a Inner<F>) -> Self {
        &(*inner).inner
    }
}
