use core::{
    cell::UnsafeCell,
    ops::Deref,
};

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
        PreparsedMessage,
        TransportMessage,
        HDF,
    },
};

// local
use crate::message::{
    announcement,
    keyload,
    signed_packet,
    subscription,
    tagged_packet,
    unsubscription,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Message<Address>
where
    Address: Link,
{
    pub address: Address,
    pub header: HDF<Address::Relative>,
    pub content: MessageContent,
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

    pub(crate) fn orphan<F>(address: Address, mut preparsed: PreparsedMessage<Vec<u8>, F, Address::Relative>) -> Self
    where
        Address::Relative: Default,
    {
        Self {
            address,
            header: preparsed.take_header(),
            content: MessageContent::Orphan(Orphan {
                cursor: preparsed.cursor(),
                message: preparsed.into_transport_msg(),
            }),
        }
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub(crate) fn into_address(self) -> Address {
        self.address
    }

    pub fn header(&self) -> &HDF<Address::Relative> {
        &self.header
    }

    pub fn content(&self) -> &MessageContent {
        &self.content
    }

    pub fn is_announcement(&self) -> bool {
        matches!(self.content, MessageContent::Announcement { .. })
    }

    pub fn is_keyload(&self) -> bool {
        matches!(self.content, MessageContent::Keyload { .. })
    }

    pub fn is_signed_packet(&self) -> bool {
        matches!(self.content, MessageContent::SignedPacket { .. })
    }

    pub fn is_tagged_packet(&self) -> bool {
        matches!(self.content, MessageContent::TaggedPacket { .. })
    }

    pub fn is_subscription(&self) -> bool {
        matches!(self.content, MessageContent::Subscription { .. })
    }

    pub fn is_unsubscription(&self) -> bool {
        matches!(self.content, MessageContent::Unsubscription { .. })
    }

    pub fn is_orphan(&self) -> bool {
        matches!(self.content, MessageContent::Orphan { .. })
    }

    pub fn as_announcement(&self) -> Option<&Announcement> {
        if let MessageContent::Announcement(announcement) = &self.content {
            Some(announcement)
        } else {
            None
        }
    }

    pub fn as_keyload(&self) -> Option<&Keyload> {
        if let MessageContent::Keyload(keyload) = &self.content {
            Some(keyload)
        } else {
            None
        }
    }

    pub fn as_signed_packet(&self) -> Option<&SignedPacket> {
        if let MessageContent::SignedPacket(signed_packet) = &self.content {
            Some(signed_packet)
        } else {
            None
        }
    }

    pub fn as_tagged_packet(&self) -> Option<&TaggedPacket> {
        if let MessageContent::TaggedPacket(tagged_packet) = &self.content {
            Some(tagged_packet)
        } else {
            None
        }
    }

    pub fn as_subscription(&self) -> Option<&Subscription> {
        if let MessageContent::Subscription(subscription) = &self.content {
            Some(subscription)
        } else {
            None
        }
    }

    pub fn as_unsubscription(&self) -> Option<&Unsubscription> {
        if let MessageContent::Unsubscription(unsubscription) = &self.content {
            Some(unsubscription)
        } else {
            None
        }
    }

    pub fn as_orphan(&self) -> Option<&Orphan> {
        if let MessageContent::Orphan(orphan) = &self.content {
            Some(orphan)
        } else {
            None
        }
    }

    /// Get the public payload of the message
    ///
    /// If the message is a [MessageContent::TaggedPacket] or [MessageContent::SignedPacket]
    /// it returns `Some(payload)`, otherwise returns `None`.  
    pub fn public_payload(&self) -> Option<&[u8]> {
        match &self.content {
            MessageContent::TaggedPacket(TaggedPacket { public_payload, .. })
            | MessageContent::SignedPacket(SignedPacket { public_payload, .. }) => Some(public_payload),
            _ => None,
        }
    }

    /// Get the masked payload of the message
    ///
    /// If the message is a [MessageContent::TaggedPacket] or [MessageContent::SignedPacket]
    /// it returns `Some(payload)`, otherwise returns `None`.  
    pub fn masked_payload(&self) -> Option<&[u8]> {
        match &self.content {
            MessageContent::TaggedPacket(TaggedPacket { masked_payload, .. })
            | MessageContent::SignedPacket(SignedPacket { masked_payload, .. }) => Some(masked_payload),
            _ => None,
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
pub enum MessageContent {
    Announcement(Announcement),
    Keyload(Keyload),
    SignedPacket(SignedPacket),
    TaggedPacket(TaggedPacket),
    Subscription(Subscription),
    Unsubscription(Unsubscription),
    Orphan(Orphan),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Announcement {
    pub author_identifier: Identifier,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Keyload {
    pub subscribers: Vec<Identifier>,
}

impl Keyload {
    pub fn includes(&self, subscriber: Identifier) -> bool {
        self.subscribers.contains(&subscriber)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedPacket {
    pub publisher_identifier: Identifier,
    pub masked_payload: Vec<u8>,
    pub public_payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TaggedPacket {
    pub masked_payload: Vec<u8>,
    pub public_payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Subscription {
    pub subscriber_identifier: Identifier,
}

impl Subscription {
    pub fn subscriber_identifier(self) -> Identifier {
        self.subscriber_identifier
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Unsubscription {
    pub subscriber_identifier: Identifier,
}

impl Unsubscription {
    pub fn subscriber_identifier(self) -> Identifier {
        self.subscriber_identifier
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Orphan {
    pub message: TransportMessage<Vec<u8>>,
    pub cursor: usize,
}

impl From<announcement::Unwrap> for MessageContent {
    fn from(announce: announcement::Unwrap) -> Self {
        Self::Announcement(Announcement {
            author_identifier: announce.author_id(),
        })
    }
}

impl<'a, F> From<subscription::Unwrap<'a, F>> for MessageContent {
    fn from(subscription: subscription::Unwrap<'a, F>) -> Self {
        Self::Subscription(Subscription {
            subscriber_identifier: subscription.subscriber_identifier(),
        })
    }
}

impl<'a, F> From<keyload::Unwrap<'a, F>> for MessageContent {
    fn from(keyload: keyload::Unwrap<'a, F>) -> Self {
        Self::Keyload(Keyload {
            subscribers: keyload.into_subscribers(),
        })
    }
}

impl<'a, F> From<signed_packet::Unwrap<'a, F>> for MessageContent {
    fn from(mut signed_packet: signed_packet::Unwrap<'a, F>) -> Self {
        Self::SignedPacket(SignedPacket {
            publisher_identifier: signed_packet.publisher_identifier(),
            masked_payload: signed_packet.take_masked_payload(),
            public_payload: signed_packet.take_public_payload(),
        })
    }
}

impl<'a, F> From<tagged_packet::Unwrap<'a, F>> for MessageContent {
    fn from(mut tagged_packet: tagged_packet::Unwrap<'a, F>) -> Self {
        Self::TaggedPacket(TaggedPacket {
            masked_payload: tagged_packet.take_masked_payload(),
            public_payload: tagged_packet.take_public_payload(),
        })
    }
}

impl<'a, F> From<unsubscription::Unwrap<'a, F>> for MessageContent {
    fn from(mut unsubscriptiokn: unsubscription::Unwrap<'a, F>) -> Self {
        Self::Unsubscription(Unsubscription {
            subscriber_identifier: unsubscriptiokn.subscriber_identifier(),
        })
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
