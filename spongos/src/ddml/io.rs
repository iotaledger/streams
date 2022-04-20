//! Lightweight abstraction, a trinary equivalent of `Write` trait allowing access to trinary slices.
use alloc::string::{String, ToString};

use anyhow::{Result, ensure};

use crate::Error::{
        StreamAllocationExceededIn,
        StreamAllocationExceededOut,
};

/// Write
pub trait OStream {
    // TODO: REMOVE
    // /// Try advance and panic in case of error.
    // fn advance<'a>(&'a mut self, n: usize) -> &'a mut [u8] {
    //     let r = self.try_advance(n);
    //     assert!(r.is_ok());
    //     r.unwrap()
    // }

    /// Try put n bytes into the stream, returning a slice to the buffer.
    fn try_advance(&mut self, bytes: usize) -> Result<&mut [u8]>;

    /// Dump stream debug info.
    fn dump(&self) -> String;
}

/// Read
pub trait IStream {
    // /// Try advance and panic in case of error.
    // fn advance<'a>(&'a mut self, n: usize) -> &'a [u8] {
    //     let r = self.try_advance(n);
    //     assert!(r.is_ok());
    //     r.unwrap()
    // }

    /// Try get n bytes from the stream, returning a slice to the buffer.
    fn try_advance<'a>(&'a mut self, n: usize) -> Result<&'a [u8]>;

    /// Dump stream debug info.
    fn dump(&self) -> String;
}

// impl<'b> OStream for &'b mut [u8] {
//     fn try_advance<'a>(&'a mut self, n: usize) -> Result<&'a mut [u8]> {
//         ensure!(n <= self.len(), StreamAllocationExceededOut(n, self.len()));
//         let (head, tail) = (*self).split_at_mut(n);
//         unsafe {
//             *self = core::mem::transmute::<&'a mut [u8], &'b mut [u8]>(tail);
//         }
//         Ok(head)
//     }

//     fn dump(&self) -> String {
//         format!("{}", hex::encode(self))
//     }
// }

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
