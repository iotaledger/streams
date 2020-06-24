use std::hash;

use crate::{
    sponge::prp::PRP,
};

/// Convenience wrapper for storing Spongos inner state.
#[derive(Clone)]
pub struct Inner<F> {
    pub inner: Vec<u8>,
    pub _phantom: std::marker::PhantomData<F>,
}

impl<F> PartialEq for Inner<F>
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}
impl<F> Eq for Inner<F> {}

impl<F> Default for Inner<F>
where
    F: PRP,
{
    fn default() -> Self {
        Self {
            inner: Vec::with_capacity(F::CAPACITY_BITS / 8),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F> hash::Hash for Inner<F>
{
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
            _phantom: std::marker::PhantomData,
        }
    }
}

/*
impl<F> From<&Inner<F>> for Spongos<F> {
    fn from(inner: &Inner<F>) -> Self {
        Self::from_inner_tbits(inner.as_ref())
    }
}

impl<F> From<Inner<F>> for Spongos<F> {
    fn from(inner: Inner<F>) -> Self {
        Self::from_inner_tbits(inner.as_ref())
    }
}

impl<F> TryFrom<&Spongos<F>> for Inner<F> {
    type Error = ();
    fn try_from(spongos: &Spongos<F>) -> Result<Self, ()> {
        if spongos.is_committed() {
            Ok(spongos.to_inner_tbits().into())
        } else {
            Err(())
        }
    }
}

impl<F> TryFrom<Spongos<F>> for Inner<F> {
    type Error = ();
    fn try_from(spongos: Spongos<F>) -> Result<Self, ()> {
        TryFrom::<&Spongos<F>>::try_from(&spongos)
    }
}
 */
