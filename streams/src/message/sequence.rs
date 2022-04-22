//! `Sequence` message _wrapping_ and _unwrapping_.
//!
//! `Sequence` messages act as a referencing lookup point for messages in a multi-branch tree. They form
//! a sequential chain of all the messages published by one publisher. Each publisher has its own chain
//! of `Sequence` messages.
//!
//! ```ddml
//! message Sequence {
//!     skip link msgid;
//!     join(msgid);
//!     match identifier:
//!       EdPubKey:
//!         mask            u8  id_type(0);
//!         mask            u8  ed25519_pubkey[32];
//!       PskId:
//!         mask            u8  id_type(1);
//!         mask            u8  psk_id[16];
//!    skip                 u64 seq_num;
//!    absorb               u8  linked_msg_id[12];
//!    commit;
//!    squeeze external     u8  hash[64];
//!    ed25519(hash)        u8  signature[64];   
//! }
//! ```
// Rust
use alloc::boxed::Box;

// 3rd-party
use anyhow::Result;
use async_trait::async_trait;

// IOTA
use crypto::signatures::ed25519;

// Streams
use spongos::{
    ddml::{
        commands::{
            sizeof,
            unwrap,
            wrap,
            Absorb,
            Commit,
            Join,
            Skip,
        },
        io,
        types::Uint64,
    },
    Spongos,
    PRP,
};
use LETS::{
    id::Identifier,
    message::{
        ContentSizeof,
        ContentUnwrap,
        ContentWrap,
    },
};

// Local
// use iota_streams_core::{
//     async_trait,
//     prelude::Box,
//     sponge::prp::PRP,
//     Result,
// };

// use iota_streams_ddml::{
//     command::*,
//     io,
//     link_store::{
//         EmptyLinkStore,
//         LinkStore,
//     },
//     types::*,
// };

pub struct Wrap<'a, F, Link> {
    initial_state: &'a mut Spongos<F>,
    id: Identifier,
    seq_num: u64,
    ref_link: &'a Link,
}

#[async_trait(?Send)]
impl<'a, F, Link> ContentSizeof<Wrap<'a, F, Link>> for sizeof::Context
where
    Self: Absorb<&'a Link>,
{
    async fn sizeof(&mut self, sequence: &Wrap<'a, F, Link>) -> Result<&mut Self> {
        self.sizeof(&sequence.id)
            .await?
            .skip(Uint64::new(sequence.seq_num))?
            .absorb(&sequence.ref_link)?
            .commit()?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<'a, F, OS, Link> ContentWrap<Wrap<'a, F, Link>> for wrap::Context<F, OS>
where
    F: PRP,
    OS: io::OStream,
    Self: Absorb<&'a Link>,
{
    async fn wrap(&mut self, sequence: &mut Wrap<'a, F, Link>) -> Result<&mut Self> {
        self.join(sequence.initial_state)?
            .wrap(&mut sequence.id)
            .await?
            .skip(Uint64::new(sequence.seq_num))?
            .absorb(&sequence.ref_link)?
            .commit()?;
        Ok(self)
    }
}

pub struct Unwrap<'a, F, Link> {
    initial_state: &'a mut Spongos<F>,
    id: Identifier,
    seq_num: u64,
    ref_link: Link,
}

#[async_trait(?Send)]
impl<'a, F, IS, Link> ContentUnwrap<Unwrap<'a, F, Link>> for unwrap::Context<F, IS>
where
    F: PRP,
    IS: io::IStream,
    Self: for<'b> Absorb<&'b mut Link>,
{
    async fn unwrap(&mut self, sequence: &mut Unwrap<'a, F, Link>) -> Result<&mut Self> {
        let mut seq_num = Uint64::default();
        self.join(sequence.initial_state)?
            .unwrap(&mut sequence.id)
            .await?
            .skip(&mut seq_num)?
            .absorb(&mut sequence.ref_link)?
            .commit()?;
        sequence.seq_num = seq_num.inner();
        Ok(self)
    }
}
