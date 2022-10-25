/// DDML `external` modifier, it changes behaviour of commands in the following way.
/// The external field is not encoded in binary representation and the value is stored in the
/// environment implicitly.
#[derive(PartialEq, Eq, Copy, Clone, Debug, Default)]
pub struct External<T>(T);

impl<T> External<T> {
    /// Wraps a variable-size object for modified `DDML` operations
    ///
    /// # Arguments
    /// * `t`: The object to encode/decode with modified behaviour.
    pub fn new(t: T) -> Self {
        Self(t)
    }

    /// Consumes the [`External`], returning the inner object `T`.
    pub(crate) fn into_inner(self) -> T {
        self.0
    }

    /// Returns a reference to the inner object `T`.
    pub(crate) fn inner(&self) -> &T {
        &self.0
    }

    /// Returns a mutable reference to the inner object `T`.
    pub(crate) fn inner_mut(&mut self) -> &mut T {
        &mut self.0
    }

    pub fn as_ref(&self) -> External<&T> {
        External::new(self.inner())
    }

    pub fn as_mut(&mut self) -> External<&mut T> {
        External::new(self.inner_mut())
    }
}

impl<I, R> AsRef<R> for External<I>
where
    I: AsRef<R>,
    R: ?Sized,
{
    fn as_ref(&self) -> &R {
        self.inner().as_ref()
    }
}

impl<I, R> AsMut<R> for External<I>
where
    I: AsMut<R>,
    R: ?Sized,
{
    fn as_mut(&mut self) -> &mut R {
        self.inner_mut().as_mut()
    }
}
