use alloc::boxed::Box;
use core::convert::{TryFrom, TryInto};

use async_trait::async_trait;

use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Absorb, Skip},
        io,
        types::{NBytes, Uint8},
    },
    error::Result as SpongosResult,
    PRP,
};

use crate::{
    error::{Error, Result},
    message::{
        content::{ContentSizeof, ContentUnwrap, ContentWrap},
        version::{FINAL_PCF_ID, INIT_PCF_ID, INTER_PCF_ID},
    },
};

/// Payload Carrying Frame. Contains the body of a Streams message
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[allow(clippy::upper_case_acronyms)]
pub struct PCF<Content> {
    /// Identifies the type of message
    frame_type: u8,
    /// Designates the position of this frame in the total message
    // 22-bit field
    payload_frame_num: PayloadFrameNum,
    /// Payload of the message
    content: Content,
}

// All PCF's are Frame Number 1 right now since the increase in tangle payload space to 32kb
impl PCF<()> {
    /// Creates a default Initial Payload Carrying Frame
    pub fn new_init_frame() -> Self {
        Self {
            frame_type: INIT_PCF_ID,
            payload_frame_num: PayloadFrameNum::from_u32_unchecked(1),
            content: (),
        }
    }

    /// Creates a default Intermediate Payload Carrying Frame
    pub fn new_inter_frame() -> Self {
        Self {
            frame_type: INTER_PCF_ID,
            payload_frame_num: PayloadFrameNum::from_u32_unchecked(1),
            content: (),
        }
    }

    /// Creates a default Final Payload Carrying Frame
    pub fn new_final_frame() -> Self {
        Self {
            frame_type: FINAL_PCF_ID,
            payload_frame_num: PayloadFrameNum::from_u32_unchecked(1),
            content: (),
        }
    }
}

impl<Content> Default for PCF<Content>
where
    Content: Default,
{
    fn default() -> Self {
        PCF::new_final_frame().with_content(Default::default())
    }
}

impl<Content> PCF<Content> {
    /// Creates a new [`PCF`] from the provided frame type, frame number and payload
    ///
    /// # Arguments
    /// * `frame_type`: Identifier for the type of message
    /// * `payload_frame_num`: Frame position
    /// * `content`: Payload of the message
    pub fn new(frame_type: u8, payload_frame_num: u32, content: Content) -> Result<Self> {
        Ok(Self {
            frame_type,
            payload_frame_num: payload_frame_num.try_into()?,
            content,
        })
    }

    /// Injects content into the payload space of the [`PCF`]
    ///
    /// # Arguments
    /// * `content`: Payload of the message
    pub fn with_content<T>(self, content: T) -> PCF<T> {
        PCF {
            frame_type: self.frame_type,
            payload_frame_num: self.payload_frame_num,
            content,
        }
    }

    /// Replaces the content field of the [`PCF`]
    ///
    /// # Arguments
    /// * `content`: New payload of the message
    pub(crate) fn change_content(&mut self, content: Content) {
        self.content = content;
    }

    /// Returns a reference to the payload of the [`PCF`]
    pub fn content(&self) -> &Content {
        &self.content
    }

    /// Consumes the [`PCF`], returning the payload content
    pub fn into_content(self) -> Content {
        self.content
    }

    /// Injects a payload frame number into the `payload_frame_num` field of the [`PCF`]
    ///
    /// # Arguments
    /// * `payload_frame_num`: Frame number of the message content
    pub fn with_payload_frame_num(&mut self, payload_frame_num: u32) -> Result<&mut Self> {
        self.payload_frame_num = payload_frame_num.try_into()?;
        Ok(self)
    }

    /// Returns the payload frame number of the message content
    pub fn payload_frame_num(&self) -> u32 {
        self.payload_frame_num.to_inner()
    }
}

#[async_trait(?Send)]
impl<Content> ContentSizeof<PCF<Content>> for sizeof::Context
where
    sizeof::Context: ContentSizeof<Content>,
{
    async fn sizeof(&mut self, pcf: &PCF<Content>) -> SpongosResult<&mut Self> {
        self.absorb(Uint8::new(pcf.frame_type))?
            .skip(pcf.payload_frame_num)?
            .sizeof(&pcf.content)
            .await?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<F, OS, Content> ContentWrap<PCF<Content>> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
    Self: ContentWrap<Content>,
{
    async fn wrap(&mut self, pcf: &mut PCF<Content>) -> SpongosResult<&mut Self>
    where
        Content: 'async_trait,
    {
        self.absorb(Uint8::new(pcf.frame_type))?
            .skip(pcf.payload_frame_num)?
            .wrap(&mut pcf.content)
            .await?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl<F, IS, Content> ContentUnwrap<PCF<Content>> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
    unwrap::Context<IS, F>: ContentUnwrap<Content>,
{
    async fn unwrap(&mut self, pcf: &mut PCF<Content>) -> SpongosResult<&mut Self> {
        let mut frame_type = Uint8::default();
        self.absorb(&mut frame_type)?
            .skip(&mut pcf.payload_frame_num)?
            .unwrap(&mut pcf.content)
            .await?;
        pcf.frame_type = frame_type.into();
        Ok(self)
    }
}

/// Frame number for sharded messages
#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct PayloadFrameNum(u32);

impl PayloadFrameNum {
    fn from_u32(frame_num: u32) -> Result<Self> {
        Self::validate(frame_num)?;
        Ok(Self::from_u32_unchecked(frame_num))
    }

    fn from_u32_unchecked(frame_num: u32) -> Self {
        Self(frame_num)
    }

    fn validate(payload_frame_num: u32) -> Result<()> {
        match payload_frame_num >> 22 == 0 {
            true => Ok(()),
            false => Err(Error::InvalidSize(
                "payload-frame-num value at most",
                22,
                payload_frame_num.try_into().unwrap(),
            )),
        }
    }

    fn to_inner(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for PayloadFrameNum {
    type Error = crate::error::Error;

    fn try_from(frame_num: u32) -> Result<Self> {
        Self::from_u32(frame_num)
    }
}

impl From<PayloadFrameNum> for NBytes<[u8; 3]> {
    fn from(frame_num: PayloadFrameNum) -> Self {
        let bytes = frame_num.to_inner().to_be_bytes();
        let mut optimized_bytes = [0; 3];
        optimized_bytes.copy_from_slice(&bytes[1..=3]);
        NBytes::new(optimized_bytes)
    }
}

impl From<NBytes<[u8; 3]>> for PayloadFrameNum {
    fn from(nbytes: NBytes<[u8; 3]>) -> Self {
        let mut bytes = [0u8; 4];
        bytes[1..=3].copy_from_slice(nbytes.inner());
        Self::from_u32_unchecked(u32::from_be_bytes(bytes))
    }
}

impl<OS, F> Skip<PayloadFrameNum> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn skip(&mut self, frame_num: PayloadFrameNum) -> SpongosResult<&mut Self> {
        self.skip(NBytes::from(frame_num))
    }
}

impl<OS, F> Skip<&mut PayloadFrameNum> for unwrap::Context<OS, F>
where
    Self: for<'a> Skip<NBytes<&'a mut [u8; 3]>>,
{
    fn skip(&mut self, frame_num: &mut PayloadFrameNum) -> SpongosResult<&mut Self> {
        let mut bytes = NBytes::new([0u8; 3]);
        self.skip(bytes.as_mut())?;
        *frame_num = bytes.into();
        Ok(self)
    }
}

impl Skip<PayloadFrameNum> for sizeof::Context {
    fn skip(&mut self, frame_num: PayloadFrameNum) -> SpongosResult<&mut Self> {
        self.skip(NBytes::from(frame_num))
    }
}
