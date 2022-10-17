use alloc::string::String;
use core::ops::{Deref, DerefMut};

use crate::error::{
    Error::{StreamAllocationExceededIn, StreamAllocationExceededOut},
    Result,
};

/// Write
pub trait OStream {
    /// Try put n bytes into the stream, returning a slice to the buffer.
    fn try_advance(&mut self, bytes: usize) -> Result<&mut [u8]>;

    /// Dump stream debug info.
    fn dump(&self) -> String;
}

/// Read
pub trait IStream {
    /// Ensure there are enough bytes left in stream for advancement
    fn ensure_size(&self, n: usize) -> Result<()>;

    /// Try get n bytes from the stream, returning a slice to the buffer.
    fn try_advance(&mut self, n: usize) -> Result<&[u8]>;

    /// Dump stream debug info.
    fn dump(&self) -> String;
}

/// Implementing the OStream trait for a mutable slice of bytes.
impl OStream for &mut [u8] {
    /// `try_advance` takes a mutable reference to a `StreamAllocator` and tries to advance the
    /// stream by a given number of bytes, producing an error if the stream is shorter than the
    /// provided length.
    ///
    /// # Arguments
    /// * `n`: The number of bytes to advance the stream by.
    ///
    /// Returns:
    /// A mutable slice of the buffer.
    fn try_advance(&mut self, n: usize) -> Result<&mut [u8]> {
        match n <= self.len() {
            true => {
                let (head, tail) = core::mem::take(self).split_at_mut(n);
                *self = tail;
                Ok(head)
            }
            false => Err(StreamAllocationExceededOut(n, self.len())),
        }
    }

    /// Returns a hexadecimal string representation of the bytes in the slice.
    ///
    /// Returns:
    /// A String
    fn dump(&self) -> String {
        hex::encode(self)
    }
}

/// Implementation of `OStream` for a mutable reference implementing `OStream`.
impl<T> OStream for &mut T
where
    T: OStream,
{
    /// `try_advance` takes a mutable reference to a `StreamAllocator` and tries to advance the
    /// stream by a given number of bytes, producing an error if the stream is shorter than the
    /// provided length.
    ///
    /// # Arguments
    /// * `n`: The number of bytes to advance the stream by.
    ///
    /// Returns:
    /// A mutable slice of the buffer.
    fn try_advance(&mut self, n: usize) -> Result<&mut [u8]> {
        self.deref_mut().try_advance(n)
    }

    /// Returns a hexadecimal string representation of the bytes in the slice.
    ///
    /// Returns:
    /// A String
    fn dump(&self) -> String {
        self.deref().dump()
    }
}

/// Implementing the IStream trait for a slice of bytes.
impl IStream for &[u8] {
    /// Ensure the input stream size is equal to or less than the number of bytes intended for
    /// allocation;
    ///
    /// # Arguments
    /// * `n`: the number of bytes we want to allocate
    ///
    /// Returns:
    /// Ok if size does not exceed allocation, Error if it does
    fn ensure_size(&self, n: usize) -> Result<()> {
        match n <= self.len() {
            true => Ok(()),
            false => Err(StreamAllocationExceededIn(n, self.len())),
        }
    }

    /// The first thing the function does is call `ensure_size` to make sure there are enough bytes
    /// in the buffer. If there aren't, it returns an error. Next the stream is split at the
    /// advancement value, returning the head of that split, and replacing self with the
    /// remainder of the slice.
    ///
    /// # Arguments
    /// * `n`: The number of bytes to advance the cursor by.
    ///
    /// Returns:
    /// A slice of the bytes in the buffer.
    fn try_advance(&mut self, n: usize) -> Result<&[u8]> {
        self.ensure_size(n)?;
        let (head, tail) = self.split_at(n);
        *self = tail;
        Ok(head)
    }

    /// Returns a hexadecimal string representation of the bytes in the slice.
    ///
    /// Returns:
    /// A String
    fn dump(&self) -> String {
        hex::encode(self)
    }
}

/// Implementation of `IStream` for a mutable reference implementing `IStream`.
impl<T> IStream for &mut T
where
    T: IStream,
{
    /// Ensure the input stream size is equal to or less than the number of bytes intended for
    /// allocation;
    ///
    /// # Arguments
    /// * `n`: the number of bytes we want to allocate
    ///
    /// Returns:
    /// Ok if size does not exceed allocation, Error if it does
    fn ensure_size(&self, n: usize) -> Result<()> {
        self.deref().ensure_size(n)
    }

    /// The first thing the function does is call `ensure_size` to make sure there are enough bytes
    /// in the buffer. If there aren't, it returns an error. Next the stream is split at the
    /// advancement value, returning the head of that split, and replacing self with the
    /// remainder of the slice.
    ///
    /// # Arguments
    /// * `n`: The number of bytes to advance the cursor by.
    ///
    /// Returns:
    /// A slice of the bytes in the buffer.
    fn try_advance(&mut self, n: usize) -> Result<&[u8]> {
        self.deref_mut().try_advance(n)
    }

    /// Returns a hexadecimal string representation of the bytes in the slice.
    ///
    /// Returns:
    /// A String
    fn dump(&self) -> String {
        self.deref().dump()
    }
}
