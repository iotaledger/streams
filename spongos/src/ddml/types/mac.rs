/// The value wrapped in Mac is just the size of message authentication tag
/// (MAC) in bytes.  The requested amount of bytes is squeezed from Spongos and
/// encoded in the binary stream during Wrap operation.  During Unwrap operation
/// the requested amount of bytes is squeezed from Spongos and compared to the
/// bytes encoded in the binary stream.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub struct Mac(usize);

impl Mac {
    /// Creates a new `Mac` object for authentication of a specified length
    ///
    /// # Arguments
    /// * `length`: The length of the `Mac`.
    ///
    /// Returns:
    /// A new `Mac` struct.
    pub const fn new(length: usize) -> Self {
        Self(length)
    }

    /// Returns:
    /// The length of the `Mac`.
    pub(crate) fn length(&self) -> usize {
        self.0
    }
}
