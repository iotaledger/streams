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

impl OStream for &mut [u8] {
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

    fn dump(&self) -> String {
        hex::encode(self)
    }
}

impl<T> OStream for &mut T
where
    T: OStream,
{
    fn try_advance(&mut self, n: usize) -> Result<&mut [u8]> {
        self.deref_mut().try_advance(n)
    }

    fn dump(&self) -> String {
        self.deref().dump()
    }
}

impl IStream for &[u8] {
    fn ensure_size(&self, n: usize) -> Result<()> {
        match n <= self.len() {
            true => Ok(()),
            false => Err(StreamAllocationExceededIn(n, self.len())),
        }
    }

    fn try_advance(&mut self, n: usize) -> Result<&[u8]> {
        self.ensure_size(n)?;
        let (head, tail) = self.split_at(n);
        *self = tail;
        Ok(head)
    }

    fn dump(&self) -> String {
        hex::encode(self)
    }
}

impl<T> IStream for &mut T
where
    T: IStream,
{
    fn ensure_size(&self, n: usize) -> Result<()> {
        self.deref().ensure_size(n)
    }

    fn try_advance(&mut self, n: usize) -> Result<&[u8]> {
        self.deref_mut().try_advance(n)
    }

    fn dump(&self) -> String {
        self.deref().dump()
    }
}
