
// TODO: REMOVE
// use generic_array::ArrayLength;
// use super::types::NBytes;

/// DDML `external` modifier, it changes behaviour of commands in the following way.
/// The external field is not encoded in trinary representation and the value is stored in the environment implicitly.
#[derive(PartialEq, Eq, Copy, Clone, Debug, Default)]
pub struct External<T>(T);

impl<T> External<T> {
    pub fn new(t: T) -> Self {
        Self(t)
    }

    pub(crate) fn into_inner(self) -> T {
        self.0
    }

    pub(crate) fn inner(&self) -> &T {
        &self.0
    }

    pub(crate) fn inner_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

// TODO: REMOVE
// impl<'a, T, N> From<T> for External<&'a NBytes<N>>
// where
//     T: Into<&'a NBytes<N>>,
//     N: ArrayLength<u8>,
// {
//     fn from(origin: T) -> Self {
//         Self(origin.into())
//     }
// }

impl<I, R> AsRef<R> for External<I> where I: AsRef<R>, R: ?Sized {
    fn as_ref(&self) -> &R {
        self.inner().as_ref()
    }
}

impl<I, R> AsMut<R> for External<I> where I: AsMut<R>, R: ?Sized{
    fn as_mut(&mut self) -> &mut R {
        self.inner_mut().as_mut()
    }
}