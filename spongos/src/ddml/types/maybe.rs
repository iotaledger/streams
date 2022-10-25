/// A `DDML` wrapper type for `Option` arguments, allowing them to be wrapped into and unwrapped
/// from a spongos stream. When being wrapped, if the `Option` is `Some(T)`, then a `1` is wrapped
/// into the stream, followed by the object itself, otherwise a `0` is wrapped to represent `None`.
/// Conversely, When unwrapping, the first byte of the stream will be parsed, and if it is  a `1`,
/// the argument is then unwrapped as well and returned as `Some(T)`. If the first byte is `0`, then
/// the `Option` is returned as `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Maybe<T>(T);

impl<T> Maybe<T> {
    /// Creates a new `Maybe` struct wrapper for the provided `Option`
    ///
    /// # Arguments
    /// * `t`: The `Option` that will be wrapped.
    ///
    /// Returns:
    /// A `Maybe` wrapper struct
    pub fn new(t: T) -> Self {
        Self(t)
    }

    /// Consumes the [`Maybe`] wrapper, returning the inner `Option`.
    pub(crate) fn into_inner(self) -> T {
        self.0
    }
}
