use core::fmt;
use iota_streams_core::Result;

use super::*;
use core::fmt::Debug;
use iota_streams_core::{
    prelude::Vec,
    sponge::prp::PRP,
};
use iota_streams_ddml::{
    command::unwrap,
    link_store::EmptyLinkStore,
    types::*,
};

/// Binary Message body with information of how to parse it.
#[derive(Clone, Hash, Default, PartialEq, Eq)]
pub struct BinaryBody {
    pub bytes: Vec<u8>,
}

/// Binary network Message representation.
pub type BinaryMessage<AbsLink> = GenericMessage<AbsLink, BinaryBody>;

impl fmt::Debug for BinaryBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: first 10 bytes of body is average HDF
        write!(f, "{}", hex::encode(&self.bytes[..10]))
    }
}

impl fmt::Display for BinaryBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.bytes[..]))
    }
}

impl From<Vec<u8>> for BinaryBody {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl<Link> BinaryMessage<Link> {
    pub async fn parse_header<F>(&self) -> Result<PreparsedMessage<'_, F, Link>>
    where
        F: PRP,
        Link: Clone + AbsorbExternalFallback<F> + HasLink + Debug,
    {
        let mut ctx = unwrap::Context::new(&self.body.bytes[..]);
        let mut header =
            HDF::<Link>::new(self.link().clone()).with_previous_msg_link(Bytes(self.prev_link().to_bytes()));
        let store = EmptyLinkStore::<F, Link, ()>::default();
        header.unwrap(&store, &mut ctx).await?;

        Ok(PreparsedMessage { header, ctx })
    }
}
