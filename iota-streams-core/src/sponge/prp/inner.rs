use std::hash;

use crate::sponge::prp::PRP;
use crate::tbits::{word::BasicTbitWord, Tbits};

/// Convenience wrapper for storing Spongos inner state.
#[derive(Clone)]
pub struct Inner<TW, F> {
    pub inner: Tbits<TW>,
    pub _phantom: std::marker::PhantomData<F>,
}

impl<TW, F> PartialEq for Inner<TW, F>
where
    TW: BasicTbitWord,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}
impl<TW, F> Eq for Inner<TW, F> where TW: BasicTbitWord {}

impl<TW, F> Default for Inner<TW, F>
where
    TW: BasicTbitWord,
    F: PRP<TW>,
{
    fn default() -> Self {
        Self {
            inner: Tbits::<TW>::zero(F::CAPACITY),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<TW, F> hash::Hash for Inner<TW, F>
where
    TW: BasicTbitWord,
    TW::Tbit: hash::Hash,
{
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (self.inner).hash(state);
    }
}

impl<TW, F> AsRef<Tbits<TW>> for Inner<TW, F> {
    fn as_ref(&self) -> &Tbits<TW> {
        &self.inner
    }
}

impl<TW, F> AsMut<Tbits<TW>> for Inner<TW, F> {
    fn as_mut(&mut self) -> &mut Tbits<TW> {
        &mut self.inner
    }
}

impl<TW, F> From<Tbits<TW>> for Inner<TW, F> {
    fn from(tbits: Tbits<TW>) -> Self {
        Self {
            inner: tbits,
            _phantom: std::marker::PhantomData,
        }
    }
}

/*
impl<TW, F> From<&Inner<TW, F>> for Spongos<TW, F> {
    fn from(inner: &Inner<TW, F>) -> Self {
        Self::from_inner_tbits(inner.as_ref())
    }
}

impl<TW, F> From<Inner<TW, F>> for Spongos<TW, F> {
    fn from(inner: Inner<TW, F>) -> Self {
        Self::from_inner_tbits(inner.as_ref())
    }
}

impl<TW, F> TryFrom<&Spongos<TW, F>> for Inner<TW, F> {
    type Error = ();
    fn try_from(spongos: &Spongos<TW, F>) -> Result<Self, ()> {
        if spongos.is_committed() {
            Ok(spongos.to_inner_tbits().into())
        } else {
            Err(())
        }
    }
}

impl<TW, F> TryFrom<Spongos<TW, F>> for Inner<TW, F> {
    type Error = ();
    fn try_from(spongos: Spongos<TW, F>) -> Result<Self, ()> {
        TryFrom::<&Spongos<TW, F>>::try_from(&spongos)
    }
}
 */
