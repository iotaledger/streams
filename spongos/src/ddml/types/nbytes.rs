use core::{
    convert::{
        AsMut,
        AsRef,
    },
    fmt,
    ops::{Add, Index, IndexMut}, slice::SliceIndex,
};

use generic_array::{
    ArrayLength,
    GenericArray,
};

// /// Fixed-size array of bytes
// ///
// /// The size of the array is known at compile time.
// #[derive(Clone, PartialEq, Eq, Debug, Default, Hash)]
// pub struct NBytes<N: ArrayLength<u8>>(GenericArray<u8, N>);

// impl<N> Copy for NBytes<N>
// where
//     N: ArrayLength<u8>,
//     N::ArrayType: Copy,
// {
// }

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Hash)]
pub struct NBytes<T>(T);

// impl<N: ArrayLength<u8>> fmt::Display for NBytes<N> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "{}", hex::encode(&self.0))
//     }
// }

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

// impl<N: ArrayLength<u8>> NBytes<N> {
//     pub(crate) fn as_slice(&self) -> &[u8] {
//         self.0.as_slice()
//     }
//     fn as_mut_slice(&mut self) -> &mut [u8] {
//         self.0.as_mut_slice()
//     }
// }

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

impl<T, Idx> Index<Idx> for NBytes<T> where T: Index<Idx> + AsRef<[u8]>, Idx: SliceIndex<[u8]> {
    type Output = Idx::Output;

    fn index(&self, index: Idx) -> &Self::Output {
        self.as_ref().index(index)
    }
}

impl<T, Idx> IndexMut<Idx> for NBytes<T> where T: IndexMut<Idx> + AsMut<[u8]> + AsRef<[u8]>, Idx: SliceIndex<[u8]> {
    fn index_mut(&mut self, index: Idx) -> &mut Self::Output {
        self.as_mut().index_mut(index)
    }
}

// impl<N: ArrayLength<u8>> AsRef<[u8]> for NBytes<N> {
//     fn as_ref(&self) -> &[u8] {
//         self.0.as_ref()
//     }
// }

// impl<N: ArrayLength<u8>> AsMut<[u8]> for NBytes<N> {
//     fn as_mut(&mut self) -> &mut [u8] {
//         self.0.as_mut()
//     }
// }

// impl<N: ArrayLength<u8>> From<GenericArray<u8, N>> for NBytes<N> {
//     fn from(ga: GenericArray<u8, N>) -> Self {
//         NBytes(ga)
//     }
// }

// impl<T> From<T> for NBytes<T> {
//     fn from(t: T) -> Self {
//         Self(t)
//     }
// }

// TODO: REMOVE
// impl<'a, N: ArrayLength<u8>> From<&'a GenericArray<u8, N>> for &'a NBytes<N> {
//     fn from(ga: &GenericArray<u8, N>) -> Self {
//         unsafe { &*(ga.as_ptr() as *const NBytes<N>) }
//     }
// }
// impl<'a, N: ArrayLength<u8>> From<&'a mut GenericArray<u8, N>> for &'a mut NBytes<N> {
//     fn from(ga: &mut GenericArray<u8, N>) -> Self {
//         unsafe { &mut *(ga.as_mut_ptr() as *mut NBytes<N>) }
//     }
// }
// impl<N: ArrayLength<u8>> Into<GenericArray<u8, N>> for NBytes<N> {
//     fn into(self) -> GenericArray<u8, N> {
//         self.0
//     }
// }
// impl<'a, N: ArrayLength<u8>> From<&'a [u8]> for &'a NBytes<N> {
//     fn from(slice: &[u8]) -> &NBytes<N> {
//         unsafe { &*(slice.as_ptr() as *const NBytes<N>) }
//     }
// }
// impl<'a, N: ArrayLength<u8>> From<&'a mut [u8]> for &'a mut NBytes<N> {
//     fn from(slice: &mut [u8]) -> &mut NBytes<N> {
//         unsafe { &mut *(slice.as_mut_ptr() as *mut NBytes<N>) }
//     }
// }

// impl<N> From<NBytes<N>> for GenericArray<u8, N>
// where
//     N: ArrayLength<u8>,
// {
//     fn from(nbytes: NBytes<N>) -> Self {
//         nbytes.0
//     }
// }

// impl<N> fmt::LowerHex for NBytes<N>
// where
//     N: ArrayLength<u8> + Add,
//     <N as Add>::Output: ArrayLength<u8>,
// {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         fmt::LowerHex::fmt(&self.0, f)
//     }
// }

// impl<N> fmt::UpperHex for NBytes<N>
// where
//     N: ArrayLength<u8> + Add,
//     <N as Add>::Output: ArrayLength<u8>,
// {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         fmt::UpperHex::fmt(&self.0, f)
//     }
// }

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
