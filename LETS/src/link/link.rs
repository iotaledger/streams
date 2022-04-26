// Rust
use alloc::vec::Vec;
use core::{
    convert::TryFrom,
    fmt,
};

// TODO: REMOVE
// use iota_streams_core::{
//     prelude::Vec,
//     Result,
// };

// 3rd-party
use anyhow::Result;

// Local
use crate::{
    id::Identifier,
    link::Cursor,
};

/// Type of "absolute" links. For http it's the absolute URL.
// trait HasLink: Sized + Default + Clone + Eq {
pub trait Link {
    /// Type of "base" links. For http it's domain name.
    type Base;
    /// Type of "relative" links. For http it's URL path.
    type Relative;

    /// Get base part of the link.
    fn base(&self) -> &Self::Base;

    fn into_base(self) -> Self::Base;

    /// Get relative part of the link.
    fn relative(&self) -> &Self::Relative;

    fn into_relative(self) -> Self::Relative;

    /// Construct absolute link from base and relative parts.
    fn from_parts(base: Self::Base, rel: Self::Relative) -> Self;

    // TODO: Review if this belongs to LETS OR ITS SPECIFIC OF STREAMS
    // /// Convert link to byte vector
    // fn to_bytes(&self) -> Vec<u8>;

    // TODO: Review if this belongs to LETS OR ITS SPECIFIC OF STREAMS
    // /// Get link from bytes
    // fn try_from_bytes(bytes: &[u8]) -> Result<Self>;
}

// TODO: REFACTOR OR REMOVE
pub trait LinkGenerator<'a, Address> {
    type Data;

    // fn init(data: Self::Data, idx: u64) -> Result<Self>;
    // fn init(initial_data: Self::InitialData) -> Self;

    fn gen(&mut self, data: Self::Data) -> Address;
}

//     /// Used by Author to generate a new application instance: channels address and announcement message identifier
//     fn gen(&mut self, id: &Identifier, idx: u64);

//     /// Used by Author to get announcement message id, it's just stored internally by link generator
//     fn get(&self) -> L;

//     /// Used by Subscriber to initialize link generator with the same state as Author
//     fn reset(&mut self, seed: L);

//     /// Used by users to pseudo-randomly generate a new uniform message link from a cursor
//     fn uniform_link_from(&self, cursor: Cursor<&L::Rel>) -> L;

//     /// Used by users to pseudo-randomly generate a new message link from a cursor
//     fn link_from<T: AsRef<[u8]>>(&self, id: T, cursor: Cursor<&L::Rel>) -> L;

// TODO: REMOVE
// /// Derive a new link and construct a header with given content type.
// fn uniform_header_from(
//     &self,
//     id: &Identifier,
//     cursor: Cursor<&Link::Rel>,
//     content_type: u8,
//     payload_length: usize,
//     seq_num: u64,
//     previous_msg_link: &Link,
// ) -> Result<HDF<Link>> {
//     HDF::new(
//         self.uniform_link_from(cursor),
//         previous_msg_link,
//         content_type,
//         payload_length,
//         seq_num,
//         id,
//     )
// }

// TODO: REMOVE
// /// Derive a new link and construct a header with given content type.
// fn header_from(
//     &self,
//     id: &Identifier,
//     cursor: Cursor<&Link::Rel>,
//     content_type: u8,
//     payload_length: usize,
//     seq_num: u64,
//     previous_msg_link: &Link,
// ) -> Result<HDF<Link>> {
//     HDF::new(
//         self.link_from(id, cursor),
//         previous_msg_link,
//         content_type,
//         payload_length,
//         seq_num,
//         id,
//     )
// }
// }

pub(crate) trait Linked<Address> {
    fn linked_msg(&self) -> &Address;
}

pub(crate) trait Addressable<Address> {
    fn address(&self) -> &Address;
}

pub(crate) trait Indexable<Index> {
    fn index(&self) -> Index;
}

pub(crate) trait Index {
    fn to_index<T>(&self) -> T
    where
        T: AsRef<[u8]>;
}
