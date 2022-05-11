// Rust
use alloc::vec::Vec;

// 3rd-party

// IOTA

// Streams
use LETS::{
    id::{
        Identifier,
        Permissioned,
    },
    link::Link,
    message::{
        Message as LetsMessage,
        PreparsedMessage,
        TransportMessage,
        HDF,
    },
};

// Local
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
    pub subscribers: Vec<Permissioned<Identifier>>,
}

impl Keyload {
    pub fn includes(&self, subscriber: Identifier) -> bool {
        self.subscribers.iter().any(|s| s.identifier() == &subscriber)
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
    fn from(unsubscriptiokn: unsubscription::Unwrap<'a, F>) -> Self {
        Self::Unsubscription(Unsubscription {
            subscriber_identifier: unsubscriptiokn.subscriber_identifier(),
        })
    }
}
