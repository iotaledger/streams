use core::ops::Deref;

// Rust
use alloc::vec::Vec;

// 3rd-party

// IOTA

// Streams
use spongos::PRP;
use LETS::{
    id::Identifier,
    link::Link,
    message::{
        Message as LetsMessage,
        TransportMessage,
        HDF,
    },
};

// local
use crate::message::{
    announce,
    keyload,
    subscribe,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Message<Address>
where
    Address: Link,
{
    address: Address,
    header: HDF<Address::Relative>,
    content: MessageContent,
}

impl<Address> Message<Address>
where
    Address: Link,
{
    pub(crate) fn from_lets_message<Unwrap>(
        address: Address,
        mut lets_message: LetsMessage<Address::Relative, Unwrap>,
    ) -> Self
    where
        Unwrap: Into<MessageContent>,
        Address::Relative: Default,
    {
        Message {
            address,
            header: lets_message.take_header(),
            content: lets_message.into_payload().into_content().into(),
        }
    }
}

// SignedPacket is 240 bytes in stack (192 + 24 + 24), which means 5 times more than
// the next biggest variant (TaggedPacket, 48 bytes), and the impossibility of inlining.
// Boxing PublicKey would usually be a net performance improvement if SignedPacket wasn't frequent.
// However, chances are it is the most frequent variant, therefore a profile must confirm there's
// enough performance improvement to justify the ergonomic drawback of re-enabling this lint
// #[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum MessageContent {
    Announce { author_identifier: Identifier },
    Keyload { subscribers: Vec<Identifier> },
    SignedPacket {},
    TaggedPacket {},
    Subscription { subscriber_identifier: Identifier },
    Unsubscribe {},
    // TODO: REMOVE?
    Unreadable(TransportMessage<Vec<u8>>),
}

impl From<announce::Unwrap> for MessageContent {
    fn from(announce: announce::Unwrap) -> Self {
        Self::Announce {
            author_identifier: announce.author_id(),
        }
    }
}

impl<'a, F> From<subscribe::Unwrap<'a, F>> for MessageContent {
    fn from(subscription: subscribe::Unwrap<'a, F>) -> Self {
        Self::Subscription {
            subscriber_identifier: subscription.subscriber_id(),
        }
    }
}

impl<'a, F> From<keyload::Unwrap<'a, F>> for MessageContent {
    fn from(keyload: keyload::Unwrap<'a, F>) -> Self {
        Self::Keyload {
            subscribers: keyload.into_subscribers(),
        }
    }
}

// impl message {
//     fn new_announce() -> Self {
//         Self::Announce
//     }

//     fn new_keyload() -> Self {
//         Self::Keyload
//     }

//     fn new_signed_packet<P, M>(id: Identifier, public_payload: P, masked_payload: M) -> Self
//     where
//         P: Into<Bytes>,
//         M: Into<Bytes>,
//     {
//         Self::SignedPacket {
//             id,
//             public_payload: public_payload.into(),
//             masked_payload: masked_payload.into(),
//         }
//     }

//     fn new_tagged_packet<P, M>(public_payload: P, masked_payload: M) -> Self
//     where
//         P: Into<Bytes>,
//         M: Into<Bytes>,
//     {
//         Self::TaggedPacket {
//             public_payload: public_payload.into(),
//             masked_payload: masked_payload.into(),
//         }
//     }

//     fn unreadable(binary: BinaryMessage) -> Self {
//         Self::Unreadable(binary)
//     }

//     fn is_announce(&self) -> bool {
//         matches!(self, MessageContent::Announce)
//     }

//     fn is_keyload(&self) -> bool {
//         matches!(self, MessageContent::Keyload)
//     }

//     fn is_signed_packet(&self) -> bool {
//         matches!(self, MessageContent::SignedPacket { .. })
//     }

//     fn is_tagged_packet(&self) -> bool {
//         matches!(self, MessageContent::TaggedPacket { .. })
//     }

//     fn is_sequence(&self) -> bool {
//         matches!(self, MessageContent::Sequence)
//     }

//     fn is_subscribe(&self) -> bool {
//         matches!(self, MessageContent::Subscribe)
//     }

//     fn is_unsubscribe(&self) -> bool {
//         matches!(self, MessageContent::Unsubscribe)
//     }

//     fn is_unreadable(&self) -> bool {
//         matches!(self, MessageContent::Unreadable(..))
//     }

//     /// Get the public payload of the message
//     ///
//     /// If the message is a [MessageContent::TaggedPacket] or [MessageContent::SignedPacket]
//     /// it returns `Some(payload)`, otherwise returns `None`.
//     fn public_payload(&self) -> Option<&Bytes> {
//         match self {
//             Self::TaggedPacket { public_payload, .. } | Self::SignedPacket { public_payload, .. } => {
//                 Some(public_payload)
//             }
//             _ => None,
//         }
//     }

//     /// Get the masked payload of the message
//     ///
//     /// If the message is a [MessageContent::TaggedPacket] or [MessageContent::SignedPacket]
//     /// it returns `Some(payload)`, otherwise returns `None`.
//     fn masked_payload(&self) -> Option<&Bytes> {
//         match self {
//             Self::TaggedPacket { masked_payload, .. } | Self::SignedPacket { masked_payload, .. } => {
//                 Some(masked_payload)
//             }
//             _ => None,
//         }
//     }
// }
