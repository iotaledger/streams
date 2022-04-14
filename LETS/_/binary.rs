use core::fmt;
use iota_streams_core::Result;

use super::*;
use iota_streams_core::{
    prelude::Vec,
    sponge::prp::PRP,
};
use iota_streams_ddml::{
    command::unwrap,
    link_store::EmptyLinkStore,
    types::*,
};

// TODO: REMOVE
// /// Binary Message body with information of how to parse it.
// #[derive(Clone, Hash, Default, PartialEq, Eq)]
// struct BinaryBody(Vec<u8>);

// impl BinaryBody {
//     fn as_bytes(&self) -> &[u8] {
//         &self.0
//     }

//     fn into_bytes(self) -> Vec<u8> {
//         self.0
//     }

//     fn to_bytes(&self) -> Vec<u8> {
//         self.0.clone()
//     }
// }
// impl fmt::Debug for BinaryBody {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         // TODO: first 10 bytes of body is average HDF
//         write!(f, "{}", hex::encode(&self.as_bytes()))
//     }
// }

// impl fmt::Display for BinaryBody {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "{}", hex::encode(self.as_bytes()[..10]))
//     }
// }

// impl From<Vec<u8>> for BinaryBody {
//     fn from(bytes: Vec<u8>) -> Self {
//         Self(bytes)
//     }
// }

// impl From<BinaryBody> for Vec<u8> {
//     fn from(body: BinaryBody) -> Self {
//         body.into_bytes()
//     }
// }

/// Binary network Message representation.
type BinaryMessage<AbsLink> = LinkedMessage<AbsLink, Vec<u8>>;

impl<AbsLink> BinaryMessage<AbsLink> {
    async fn parse_header<F>(&self) -> Result<PreparsedMessage<'_, F, AbsLink>>
    where
        F: PRP,
        AbsLink: Clone + AbsorbExternalFallback<F> + HasLink,
    {
        let mut ctx = unwrap::Context::new(self.body.as_bytes());
        let mut header =
            HDF::<AbsLink>::new(self.link().clone()).with_previous_msg_link(Bytes(self.prev_link().to_bytes()));
        let store = EmptyLinkStore::<F, AbsLink, ()>::default();
        header.unwrap(&store, &mut ctx).await?;

        Ok(PreparsedMessage { header, ctx })
    }
}

impl<Link> AsRef<BinaryMessage<Link>> for BinaryMessage<Link> {
    fn as_ref(&self) -> &BinaryMessage<Link> {
        self
    }
}
