// Rust
use alloc::vec::Vec;

// 3rd-party

// IOTA

// Streams
use lets::{
    address::Address,
    id::{Identifier, Permissioned, PskId},
    message::{Message as LetsMessage, PreparsedMessage, Topic, TopicHash, TransportMessage, HDF},
};

// Local
use crate::message::{
    announcement, branch_announcement, keyload, signed_packet, subscription, tagged_packet, unsubscription,
};

/// A processed Streams message
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Message {
    /// The [`Address`] of the message
    pub address: Address,
    /// The message [header](`HDF`)
    pub header: HDF,
    /// The message payload
    pub content: MessageContent,
}

impl Message {
    /// Creates a [`Message`] from a [`LetsMessage`] and the message [`Address`]
    ///
    /// # Arguments
    /// * `address`: The [`Address`] of the message.
    /// * `lets_message`: The raw message from transport
    ///
    /// Returns:
    /// A [`Message`] struct
    pub(crate) fn from_lets_message<Unwrap>(address: Address, lets_message: LetsMessage<Unwrap>) -> Self
    where
        Unwrap: Into<MessageContent>,
    {
        let parts = lets_message.into_parts();
        Message {
            address,
            header: parts.0,
            content: parts.1.into_content().into(),
        }
    }

    /// Create a generic `Orphan` message, meaning that the previous link address does not match any
    /// spongos in store, and the message cannot be processed.
    ///
    /// # Arguments
    /// * `address`: The [`Address`] of the message
    /// * `preparsed`: The [`PreparsedMessage`] that could not be processed
    ///
    /// Returns:
    /// An `Orphan` [`Message`]
    pub(crate) fn orphan(address: Address, preparsed: PreparsedMessage) -> Self {
        let parts = preparsed.into_parts();
        Self {
            address,
            header: parts.0,
            content: MessageContent::Orphan(Orphan {
                cursor: parts.3,
                message: parts.1,
            }),
        }
    }

    /// Returns the [`Address`] of the message
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns a reference to the [header](`HDF`) of the message
    pub fn header(&self) -> &HDF {
        &self.header
    }

    /// Returns a reference to the [payload](`MessageContent`) of the message
    pub fn content(&self) -> &MessageContent {
        &self.content
    }

    /// Returns a reference to the [header](`HDF`) [`TopicHash`]
    pub fn topic_hash(&self) -> &TopicHash {
        self.header.topic_hash()
    }

    /// Returns true if the message is a [`MessageContent`]`::Announcement`
    pub fn is_announcement(&self) -> bool {
        matches!(self.content, MessageContent::Announcement { .. })
    }

    /// Returns true if the message is a [`MessageContent`]`::BranchAnnouncement`
    pub fn is_branch_announcement(&self) -> bool {
        matches!(self.content, MessageContent::BranchAnnouncement { .. })
    }

    /// Returns true if the message is a [`MessageContent`]`::Keyload`
    pub fn is_keyload(&self) -> bool {
        matches!(self.content, MessageContent::Keyload { .. })
    }

    /// Returns true if the message is a [`MessageContent`]`::SignedPacket`
    pub fn is_signed_packet(&self) -> bool {
        matches!(self.content, MessageContent::SignedPacket { .. })
    }

    /// Returns true if the message is a [`MessageContent`]`::TaggedPacket`
    pub fn is_tagged_packet(&self) -> bool {
        matches!(self.content, MessageContent::TaggedPacket { .. })
    }

    /// Returns true if the message is a [`MessageContent`]`::Subscription`
    pub fn is_subscription(&self) -> bool {
        matches!(self.content, MessageContent::Subscription { .. })
    }

    /// Returns true if the message is a [`MessageContent`]`::Unsubscription`
    pub fn is_unsubscription(&self) -> bool {
        matches!(self.content, MessageContent::Unsubscription { .. })
    }

    /// Returns true if the message is a [`MessageContent`]`::Orphan`
    pub fn is_orphan(&self) -> bool {
        matches!(self.content, MessageContent::Orphan { .. })
    }

    /// If the message is an `Announcement` return it as one
    pub fn as_announcement(&self) -> Option<&Announcement> {
        if let MessageContent::Announcement(announcement) = &self.content {
            Some(announcement)
        } else {
            None
        }
    }

    /// If the message is a `BranchAnnouncement` return it as one
    pub fn as_branch_announcement(&self) -> Option<&BranchAnnouncement> {
        if let MessageContent::BranchAnnouncement(branch_announcement) = &self.content {
            Some(branch_announcement)
        } else {
            None
        }
    }

    /// If the message is a `Keyload` return it as one
    pub fn as_keyload(&self) -> Option<&Keyload> {
        if let MessageContent::Keyload(keyload) = &self.content {
            Some(keyload)
        } else {
            None
        }
    }

    /// If the message is a `SignedPacket` return it as one
    pub fn as_signed_packet(&self) -> Option<&SignedPacket> {
        if let MessageContent::SignedPacket(signed_packet) = &self.content {
            Some(signed_packet)
        } else {
            None
        }
    }

    /// If the message is a `TaggedPacket` return it as one
    pub fn as_tagged_packet(&self) -> Option<&TaggedPacket> {
        if let MessageContent::TaggedPacket(tagged_packet) = &self.content {
            Some(tagged_packet)
        } else {
            None
        }
    }

    /// If the message is a `Subscription` return it as one
    pub fn as_subscription(&self) -> Option<&Subscription> {
        if let MessageContent::Subscription(subscription) = &self.content {
            Some(subscription)
        } else {
            None
        }
    }

    /// If the message is a `Unsubscription` return it as one
    pub fn as_unsubscription(&self) -> Option<&Unsubscription> {
        if let MessageContent::Unsubscription(unsubscription) = &self.content {
            Some(unsubscription)
        } else {
            None
        }
    }

    /// If the message is an `Orphan` return it as one
    pub fn as_orphan(&self) -> Option<&Orphan> {
        if let MessageContent::Orphan(orphan) = &self.content {
            Some(orphan)
        } else {
            None
        }
    }

    /// Get the public payload of the message
    ///
    /// If the message is a [`MessageContent`]`::TaggedPacket` or [`MessageContent`]`::SignedPacket`
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
    /// If the message is a [`MessageContent`]`::TaggedPacket` or [`MessageContent`]`::SignedPacket`
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
    BranchAnnouncement(BranchAnnouncement),
    Keyload(Keyload),
    SignedPacket(SignedPacket),
    TaggedPacket(TaggedPacket),
    Subscription(Subscription),
    Unsubscription(Unsubscription),
    Orphan(Orphan),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Announcement {
    pub author_identifier: Identifier,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BranchAnnouncement {
    pub topic: Topic,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Keyload {
    pub subscribers: Vec<Permissioned<Identifier>>,
    pub psks: Vec<PskId>,
}

impl Keyload {
    /// Returns true if the provided subscriber [`Identifier`] is present in the subscribers list
    pub fn includes_subscriber(&self, subscriber: &Identifier) -> bool {
        self.subscribers.iter().any(|s| s.identifier() == subscriber)
    }

    /// Returns true if the provided [`PskId`] is present in the psks list
    pub fn includes_psk(&self, psk_id: &PskId) -> bool {
        self.psks.iter().any(|id| id == psk_id)
    }
}

/// Signed Packet [`Message`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedPacket {
    /// The [`Identifier`] of the publisher
    pub publisher_identifier: Identifier,
    /// A payload that was encrypted
    pub masked_payload: Vec<u8>,
    /// A payload that was not encrypted
    pub public_payload: Vec<u8>,
}

/// Tagged Packet [`Message`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TaggedPacket {
    /// A payload that was encrypted
    pub masked_payload: Vec<u8>,
    /// A payload that was not encrypted
    pub public_payload: Vec<u8>,
}

/// Subscription [`Message`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Subscription {
    /// [`Identifier`] of the subscribing user
    pub subscriber_identifier: Identifier,
}

impl Subscription {
    /// Returns a reference to the subscriber [`Identifier`]
    pub fn subscriber_identifier(&self) -> &Identifier {
        &self.subscriber_identifier
    }
}

/// Unsubscription [`Message`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Unsubscription {
    /// [`Identifier`] of the unsusbscribing user
    pub subscriber_identifier: Identifier,
}

impl Unsubscription {
    /// Consumes the Unsubscription and returns the the  [`Identifier`] of the subscriber
    pub fn into_subscriber_identifier(self) -> Identifier {
        self.subscriber_identifier
    }
}

/// Orphan [`Message`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Orphan {
    /// Raw message that could not be processed
    pub message: TransportMessage,
    /// Publisher cursor
    pub cursor: usize,
}

impl From<announcement::Unwrap> for MessageContent {
    fn from(announce: announcement::Unwrap) -> Self {
        Self::Announcement(Announcement {
            author_identifier: announce.into_author_id(),
        })
    }
}

impl<'a> From<branch_announcement::Unwrap<'a>> for MessageContent {
    fn from(branch_announcement: branch_announcement::Unwrap<'a>) -> Self {
        Self::BranchAnnouncement(BranchAnnouncement {
            topic: branch_announcement.into_new_topic(),
        })
    }
}

impl<'a> From<subscription::Unwrap<'a>> for MessageContent {
    fn from(subscription: subscription::Unwrap<'a>) -> Self {
        Self::Subscription(Subscription {
            subscriber_identifier: subscription.into_subscriber_identifier(),
        })
    }
}

impl<'a> From<keyload::Unwrap<'a>> for MessageContent {
    fn from(keyload: keyload::Unwrap<'a>) -> Self {
        Self::Keyload(Keyload {
            psks: keyload.psks,
            subscribers: keyload.subscribers,
        })
    }
}

impl<'a> From<signed_packet::Unwrap<'a>> for MessageContent {
    fn from(mut signed_packet: signed_packet::Unwrap<'a>) -> Self {
        let masked_payload = signed_packet.take_masked_payload();
        let public_payload = signed_packet.take_public_payload();
        Self::SignedPacket(SignedPacket {
            publisher_identifier: signed_packet.into_publisher_identifier(),
            masked_payload,
            public_payload,
        })
    }
}

impl<'a> From<tagged_packet::Unwrap<'a>> for MessageContent {
    fn from(mut tagged_packet: tagged_packet::Unwrap<'a>) -> Self {
        Self::TaggedPacket(TaggedPacket {
            masked_payload: tagged_packet.take_masked_payload(),
            public_payload: tagged_packet.take_public_payload(),
        })
    }
}

impl<'a> From<unsubscription::Unwrap<'a>> for MessageContent {
    fn from(unsubscription: unsubscription::Unwrap<'a>) -> Self {
        Self::Unsubscription(Unsubscription {
            subscriber_identifier: unsubscription.into_subscriber_identifier(),
        })
    }
}
