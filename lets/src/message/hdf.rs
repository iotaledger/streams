use alloc::boxed::Box;
use async_trait::async_trait;

use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Absorb, Commit, Guard, Mask, Skip, Squeeze},
        io,
        modifiers::External,
        types::{Mac, Maybe, NBytes, Size, Uint8},
    },
    PRP,
    error::{
        Error as SpongosError,
        Result as SpongosResult
    },
};

use crate::{
    address::MsgId,
    error::{Result, Error},
    id::Identifier,
    message::{
        content::{ContentSizeof, ContentUnwrap, ContentWrap},
        topic::{Topic, TopicHash},
        version::{HDF_ID, STREAMS_1_VER, UTF8},
    },
};

const MAC: Mac = Mac::new(32);

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub struct HDF {
    encoding: u8,
    pub version: u8,
    // content type is 4 bits
    pub message_type: u8,
    // payload length is 10 bits
    payload_length: u16,
    frame_type: u8,
    // frame count is 22 bits
    payload_frame_count: u32,
    pub linked_msg_address: Option<MsgId>,
    pub sequence: usize,
    pub publisher: Identifier,
    pub topic_hash: TopicHash,
}

impl Default for HDF {
    fn default() -> Self {
        Self {
            encoding: UTF8,
            version: STREAMS_1_VER,
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
    /// Create a new HDF
    ///
    /// In debug builds, this constructor checks that the message_type fits the maximum size
    /// expected for this field (4 bits) and panics if it exceeds it. In release builds, the
    /// check is not performed and the constructor won't panic, but only the last 4 bits of the
    /// u8 will be considered when wrapping, without emiting an explicit error.
    pub fn new(message_type: u8, sequence: usize, publisher: Identifier, topic: &Topic) -> Self {
        debug_assert!(
            message_type >> 4 == 0,
            "invalid content-type '{}': content-type value cannot be greater than 4 bits",
            message_type
        );
        Self {
            encoding: UTF8,
            version: STREAMS_1_VER,
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

    pub fn with_linked_msg_address(mut self, address: MsgId) -> Self {
        self.linked_msg_address = Some(address);
        self
    }

    pub fn with_payload_length(mut self, payload_length: u16) -> Result<Self> {
        match payload_length >> 10 == 0 {
            true => {
                self.payload_length = payload_length;
                Ok(self)
            },
            false => Err(Error::InvalidSize("payload_length" , 10, payload_length.into()))
        }
    }

    pub fn message_type(&self) -> u8 {
        self.message_type
    }

    pub fn payload_length(&self) -> u16 {
        self.payload_length
    }

    pub fn payload_frame_count(&self) -> u32 {
        self.payload_frame_count
    }

    pub fn publisher(&self) -> &Identifier {
        &self.publisher
    }

    pub fn sequence(&self) -> usize {
        self.sequence
    }

    pub fn linked_msg_address(&self) -> Option<MsgId> {
        self.linked_msg_address
    }

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
            .guard(version.inner() == STREAMS_1_VER, SpongosError::Version("Msg", version.inner()))?
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
