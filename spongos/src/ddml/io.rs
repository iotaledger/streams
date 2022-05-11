// TODO: REMOVE Traits, make inherent?
use alloc::string::String;
use core::ops::{
    Deref,
    DerefMut,
};

use anyhow::{
    ensure,
    Result,
};

use crate::Error::{
    StreamAllocationExceededIn,
    StreamAllocationExceededOut,
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
    /// Try get n bytes from the stream, returning a slice to the buffer.
    fn try_advance(&mut self, n: usize) -> Result<&[u8]>;

    /// Dump stream debug info.
    fn dump(&self) -> String;
}

impl OStream for &mut [u8] {
    fn try_advance(&mut self, n: usize) -> Result<&mut [u8]> {
        ensure!(n <= self.len(), StreamAllocationExceededOut(n, self.len()));
        let (head, tail) = core::mem::take(self).split_at_mut(n);
        *self = tail;
        Ok(head)
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
    fn try_advance(&mut self, n: usize) -> Result<&[u8]> {
        ensure!(n <= self.len(), StreamAllocationExceededIn(n, self.len()));
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
    fn try_advance(&mut self, n: usize) -> Result<&[u8]> {
        self.deref_mut().try_advance(n)
    }

    fn dump(&self) -> String {
        self.deref().dump()
    }
}
