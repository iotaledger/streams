use alloc::boxed::Box;
use async_trait::async_trait;

use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Absorb, Commit, Guard, Mask, Skip, Squeeze},
        io,
        modifiers::External,
        types::{Mac, Maybe, NBytes, Size, Uint8},
    },
    error::{Error as SpongosError, Result as SpongosResult},
    PRP,
};

use crate::{
    address::MsgId,
    error::{Error, Result},
    id::Identifier,
    message::{
        content::{ContentSizeof, ContentUnwrap, ContentWrap},
        topic::{Topic, TopicHash},
        version::{HDF_ID, STREAMS_VER, UTF8},
    },
};

/// [`Mac`] for content verification
const MAC: Mac = Mac::new(32);

/// The header of a `Streams` message
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub struct HDF {
    /// Payload encoding
    encoding: u8,
    /// Streams version
    pub version: u8,
    /// Message type identifier
    // content type is 4 bits
    pub message_type: u8,
    /// Length of the payload of the message (can be set to 0)
    // payload length is 10 bits
    payload_length: u16,
    /// Frame type of [`crate::message::PCF`] for the message
    frame_type: u8,
    /// Number of [`crate::message::PCF`] messages to expect for full message
    // frame count is 22 bits
    payload_frame_count: u32,
    /// Link to previous message in Stream
    pub linked_msg_address: Option<MsgId>,
    /// Publisher sequence number
    pub sequence: usize,
    /// Publisher [`Identifier`]
    pub publisher: Identifier,
    /// Hash of branch [`Topic`]
    pub topic_hash: TopicHash,
}

impl Default for HDF {
    fn default() -> Self {
        Self {
            encoding: UTF8,
            version: STREAMS_VER,
            message_type: 0,
            payload_length: 0,
            frame_type: HDF_ID,
            payload_frame_count: 0,
            linked_msg_address: Default::default(),
            sequence: 0,
            publisher: Default::default(),
            topic_hash: Default::default(),
        }
    }
}

impl HDF {
    /// Create a new [`HDF`] from the provided values
    ///
    /// # Arguments
    /// * `message_type`: Message type identifier
    /// * `sequence`: Publisher sequence number
    /// * `publisher`: Publisher [`Identifier`]
    /// * `topic`: Reference to branch [`Topic`]
    pub fn new(message_type: u8, sequence: usize, publisher: Identifier, topic: &Topic) -> Self {
        debug_assert!(
            message_type >> 4 == 0,
            "invalid content-type '{}': content-type value cannot be greater than 4 bits",
            message_type
        );
        Self {
            encoding: UTF8,
            version: STREAMS_VER,
            message_type,
            payload_length: 0,
            frame_type: HDF_ID,
            payload_frame_count: 0,
            linked_msg_address: None,
            sequence,
            publisher,
            topic_hash: topic.into(),
        }
    }

    /// Injects a linked message address into the [`HDF`]
    ///
    /// # Arguments
    /// * `address`: The [`MsgId`] of the previous message
    pub fn with_linked_msg_address(mut self, address: MsgId) -> Self {
        self.linked_msg_address = Some(address);
        self
    }

    /// Injects a payload length into the [`HDF`]. Can be a maximum of 10 bits in size
    ///
    /// # Arguments
    /// * `payload_length`: The length of the payload
    pub fn with_payload_length(mut self, payload_length: u16) -> Result<Self> {
        match payload_length >> 10 == 0 {
            true => {
                self.payload_length = payload_length;
                Ok(self)
            }
            false => Err(Error::InvalidSize("payload_length", 10, payload_length.into())),
        }
    }

    /// Returns the message type for the associated payload
    pub fn message_type(&self) -> u8 {
        self.message_type
    }

    /// Returns the length of the associated payload
    pub fn payload_length(&self) -> u16 {
        self.payload_length
    }

    /// Returns the frame count of the associated payload
    pub fn payload_frame_count(&self) -> u32 {
        self.payload_frame_count
    }

    /// Returns a reference to the publisher [`Identifier`]
    pub fn publisher(&self) -> &Identifier {
        &self.publisher
    }

    /// Returns the publisher sequence number
    pub fn sequence(&self) -> usize {
        self.sequence
    }

    /// Returns an `Option` for the linked message [`MsgId`]
    pub fn linked_msg_address(&self) -> Option<MsgId> {
        self.linked_msg_address
    }

    /// Returns a reference to the [`TopicHash`] representing a branch
    pub fn topic_hash(&self) -> &TopicHash {
        &self.topic_hash
    }
}

#[async_trait(?Send)]
impl ContentSizeof<HDF> for sizeof::Context {
    async fn sizeof(&mut self, hdf: &HDF) -> SpongosResult<&mut Self> {
        let message_type_and_payload_length = NBytes::<[u8; 2]>::default();
        let payload_frame_count = NBytes::<[u8; 3]>::default();
        self.absorb(Uint8::new(hdf.encoding))?
            .absorb(Uint8::new(hdf.version))?
            .skip(message_type_and_payload_length)?
            .absorb(External::new(Uint8::new(hdf.message_type << 4)))?
            .absorb(Uint8::new(hdf.frame_type))?
            .skip(payload_frame_count)?
            .absorb(Maybe::new(hdf.linked_msg_address.as_ref()))?
            .mask(&hdf.topic_hash)?
            .mask(&hdf.publisher)?
            .skip(Size::new(hdf.sequence))?
            .commit()?
            .squeeze(&MAC)?;

        Ok(self)
    }
}

#[async_trait(?Send)]
impl<F, OS> ContentWrap<HDF> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    async fn wrap(&mut self, hdf: &mut HDF) -> SpongosResult<&mut Self> {
        let message_type_and_payload_length = {
            let mut nbytes = NBytes::<[u8; 2]>::default();
            nbytes[0] = (hdf.message_type << 4) | ((hdf.payload_length >> 8) as u8 & 0b0011);
            nbytes[1] = hdf.payload_length as u8;
            nbytes
        };
        let payload_frame_count = {
            let mut nbytes = NBytes::<[u8; 3]>::default();
            let x = hdf.payload_frame_count.to_be_bytes();
            nbytes[0] = x[1] & 0b00111111;
            nbytes[1] = x[2];
            nbytes[2] = x[3];
            nbytes
        };

        self.absorb(Uint8::new(hdf.encoding))?
            .absorb(Uint8::new(hdf.version))?
            .skip(message_type_and_payload_length)?
            .absorb(External::new(Uint8::new(hdf.message_type << 4)))?
            .absorb(Uint8::new(hdf.frame_type))?
            .skip(payload_frame_count)?
            .absorb(Maybe::new(hdf.linked_msg_address.as_ref()))?
            .mask(&hdf.topic_hash)?
            .mask(&hdf.publisher)?
            .skip(Size::new(hdf.sequence))?
            .commit()?
            .squeeze(&MAC)?;

        Ok(self)
    }
}

#[async_trait(?Send)]
impl<F, IS> ContentUnwrap<HDF> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    async fn unwrap(&mut self, mut hdf: &mut HDF) -> SpongosResult<&mut Self> {
        let mut encoding = Uint8::default();
        let mut version = Uint8::default();
        // [message_type x 4][reserved x 2][payload_length x 2]
        // [payload_length x 8 -------------------------------]
        let mut message_type_and_payload_length = NBytes::<[u8; 2]>::default();
        let mut frame_type = Uint8::default();
        let mut payload_frame_count_bytes = NBytes::<[u8; 3]>::default();
        let mut seq_num = Size::default();

        self.absorb(&mut encoding)?
            .absorb(&mut version)?
            .guard(
                version.inner() == STREAMS_VER,
                SpongosError::Version("Msg", version.inner()),
            )?
            .skip(message_type_and_payload_length.as_mut())?
            .guard(
                0 == message_type_and_payload_length[0] & 0b1100,
                SpongosError::Reserved("bits 5 and 6 between content-type and payload-length"),
            )?
            .absorb(External::new(Uint8::new(
                // Absorb only message_type
                message_type_and_payload_length[0] & 0b11110000,
            )))?
            .absorb(&mut frame_type)?
            .guard(
                frame_type.inner() == HDF_ID,
                SpongosError::InvalidOption("message", frame_type.inner()),
            )?
            .skip(payload_frame_count_bytes.as_mut())?
            .guard(
                0 == payload_frame_count_bytes[0] & 0b1100,
                SpongosError::Reserved("first 2 bits of payload-frame-count"),
            )?
            .absorb(Maybe::new(&mut hdf.linked_msg_address))?
            .mask(&mut hdf.topic_hash)?
            .mask(&mut hdf.publisher)?
            .skip(&mut seq_num)?
            .commit()?
            .squeeze(&MAC)?;

        hdf.encoding = encoding.inner();
        hdf.version = version.inner();
        hdf.message_type = message_type_and_payload_length[0] >> 4;
        hdf.payload_length =
            (((message_type_and_payload_length[0] & 0b0011) as u16) << 8) | (message_type_and_payload_length[1] as u16);
        hdf.frame_type = frame_type.inner();

        let mut x = [0u8; 4];
        x[1] = payload_frame_count_bytes[0];
        x[2] = payload_frame_count_bytes[1];
        x[3] = payload_frame_count_bytes[2];
        hdf.payload_frame_count = u32::from_be_bytes(x);
        hdf.sequence = seq_num.inner();

        Ok(self)
    }
}
