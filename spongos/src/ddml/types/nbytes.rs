use core::{
    convert::{AsMut, AsRef},
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

/// Size specified byte array wrapper for `DDML` operations
#[derive(Clone, PartialEq, Eq, Debug, Default, Hash)]
// Don't implement Copy, to avoid unexpected behaviour when taken by value by mistake
pub struct NBytes<T>(T);

impl<T> NBytes<T> {
    /// Wraps a fixed-size array of bytes for `DDML` operations
    ///
    /// # Arguments
    /// * `bytes`: The byte array to be wrapped.
    pub fn new(t: T) -> Self {
        Self(t)
    }

    /// Returns a reference to the inner byte array as a slice.
    pub fn as_slice(&self) -> &[u8]
    where
        T: AsRef<[u8]>,
    {
        self.0.as_ref()
    }

    /// Returns a reference to the inner byte array as a mutable slice.
    fn as_mut_slice(&mut self) -> &mut [u8]
    where
        T: AsMut<[u8]>,
    {
        self.0.as_mut()
    }

    /// Returns a reference to the inner byte array.
    pub fn inner(&self) -> &T {
        &self.0
    }

    /// Returns a mutable reference to the inner byte array.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.0
    }

    pub fn as_ref(&self) -> NBytes<&T> {
        NBytes::new(self.inner())
    }

    pub fn as_mut(&mut self) -> NBytes<&mut T> {
        NBytes::new(self.inner_mut())
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
        self.inner().as_ref().index(index)
    }
}

impl<T, Idx> IndexMut<Idx> for NBytes<T>
where
    T: IndexMut<Idx> + AsMut<[u8]> + AsRef<[u8]>,
    Idx: SliceIndex<[u8]>,
{
    fn index_mut(&mut self, index: Idx) -> &mut Self::Output {
        self.inner_mut().as_mut().index_mut(index)
    }
}

impl<T> rand::distributions::Distribution<NBytes<T>> for rand::distributions::Standard
where
    T: AsMut<[u8]> + Default,
{
    /// Create a randomized array for a specific object type. A default of that object will be
    /// generated and filled with random bytes before being returned.
    ///
    /// # Arguments
    /// * `rng`: The random number generator to use.
    ///
    /// Returns:
    /// A random number of bytes.
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> NBytes<T> {
        let mut nbytes = NBytes::default();
        rng.fill(nbytes.as_mut_slice());
        nbytes
    }
}
