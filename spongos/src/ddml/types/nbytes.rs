use core::{
    convert::{
        AsMut,
        AsRef,
    },
    ops::{
        Index,
        IndexMut,
    },
    slice::SliceIndex,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Hash)]
pub struct NBytes<T>(T);

impl<T> NBytes<T> {
    pub fn new(t: T) -> Self {
        Self(t)
    }

    pub fn as_slice(&self) -> &[u8]
    where
        T: AsRef<[u8]>,
    {
        self.0.as_ref()
    }

    fn as_mut_slice(&mut self) -> &mut [u8]
    where
        T: AsMut<[u8]>,
    {
        self.0.as_mut()
    }

    pub(crate) fn inner(&self) -> &T {
        &self.0
    }

    pub(crate) fn inner_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> AsRef<[u8]> for NBytes<T>
where
    T: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T> AsMut<[u8]> for NBytes<T>
where
    T: AsMut<[u8]>,
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<T, Idx> Index<Idx> for NBytes<T>
where
    T: Index<Idx> + AsRef<[u8]>,
    Idx: SliceIndex<[u8]>,
{
    type Output = Idx::Output;

    fn index(&self, index: Idx) -> &Self::Output {
        self.as_ref().index(index)
    }
}

impl<T, Idx> IndexMut<Idx> for NBytes<T>
where
    T: IndexMut<Idx> + AsMut<[u8]> + AsRef<[u8]>,
    Idx: SliceIndex<[u8]>,
{
    fn index_mut(&mut self, index: Idx) -> &mut Self::Output {
        self.as_mut().index_mut(index)
    }
}

impl<T> rand::distributions::Distribution<NBytes<T>> for rand::distributions::Standard
where
    T: AsMut<[u8]> + Default,
{
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> NBytes<T> {
        let mut nbytes = NBytes::default();
        rng.fill(nbytes.as_mut_slice());
        nbytes
    }
}
