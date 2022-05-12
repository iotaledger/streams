use alloc::boxed::Box;

use anyhow::{
    anyhow,
    ensure,
    Result,
};
use async_trait::async_trait;

use spongos::{
    ddml::{
        commands::{
            sizeof,
            unwrap,
            wrap,
            Absorb,
            Guard,
            Mask,
            Skip,
        },
        io,
        modifiers::External,
        types::{
            Maybe,
            NBytes,
            Size,
            Uint8,
        },
    },
    PRP,
};

use crate::{
    id::Identifier,
    message::{
        content::{
            ContentSizeof,
            ContentUnwrap,
            ContentWrap,
        },
        version::{
            HDF_ID,
            STREAMS_1_VER,
            UTF8,
        },
    },
};

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub struct HDF<Address> {
    encoding: u8,
    pub version: u8,
    // content type is 4 bits
    pub message_type: u8,
    // payload length is 10 bits
    payload_length: u16,
    frame_type: u8,
    // frame count is 22 bits
    payload_frame_count: u32,
    pub linked_msg_address: Option<Address>,
    pub sequence: usize,
    pub publisher: Identifier,
}

impl<Address> Default for HDF<Address>
where
    Address: Default,
{
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
        }
    }
}

impl<Address> HDF<Address> {
    pub fn new(message_type: u8, sequence: usize, publisher: Identifier) -> Result<Self> {
        ensure!(
            message_type >> 4 == 0,
            anyhow!(
                "invalid content-type '{}': content-type value cannot be greater than 4 bits",
                message_type
            )
        );
        Ok(Self {
            encoding: UTF8,
            version: STREAMS_1_VER,
            message_type,
            payload_length: 0,
            frame_type: HDF_ID,
            payload_frame_count: 0,
            linked_msg_address: None,
            sequence,
            publisher,
        })
    }

    pub fn with_linked_msg_address(mut self, address: Address) -> Self {
        self.linked_msg_address = Some(address);
        self
    }

    fn with_payload_length(mut self, payload_length: u16) -> Result<Self> {
        ensure!(
            payload_length >> 10 == 0,
            anyhow!(
                "invalid payload_length '{}': payload length value cannot be larger than 10 bits",
                payload_length
            )
        );
        self.payload_length = payload_length;
        Ok(self)
    }

    pub fn message_type(&self) -> u8 {
        self.message_type
    }

    fn payload_length(&self) -> u16 {
        self.payload_length
    }

    fn payload_frame_count(&self) -> u32 {
        self.payload_frame_count
    }

    pub fn publisher(&self) -> Identifier {
        self.publisher
    }

    pub fn sequence(&self) -> usize {
        self.sequence
    }

    pub fn linked_msg_address(&self) -> &Option<Address> {
        &self.linked_msg_address
    }
}

#[async_trait(?Send)]
impl<Address> ContentSizeof<HDF<Address>> for sizeof::Context
where
    for<'a> Self: Absorb<&'a Address> + Absorb<&'a ()>,
{
    async fn sizeof(&mut self, hdf: &HDF<Address>) -> Result<&mut Self> {
        let message_type_and_payload_length = NBytes::<[u8; 2]>::default();
        let payload_frame_count = NBytes::<[u8; 3]>::default();
        self.absorb(Uint8::new(hdf.encoding))?
            .absorb(Uint8::new(hdf.version))?
            .skip(&message_type_and_payload_length)?
            .absorb(External::new(Uint8::new(hdf.message_type << 4)))?
            .absorb(Uint8::new(hdf.frame_type))?
            .skip(&payload_frame_count)?
            .absorb(Maybe::new(hdf.linked_msg_address.as_ref()))?
            .mask(&hdf.publisher)?
            .skip(Size::new(hdf.sequence))?;

        Ok(self)
    }
}

#[async_trait(?Send)]
impl<F, OS, Address> ContentWrap<HDF<Address>> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
    Self: for<'a> Absorb<&'a Address> + Absorb<Uint8>,
{
    async fn wrap(&mut self, hdf: &mut HDF<Address>) -> Result<&mut Self> {
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
            .skip(&message_type_and_payload_length)?
            .absorb(External::new(Uint8::new(hdf.message_type << 4)))?
            .absorb(Uint8::new(hdf.frame_type))?
            .skip(&payload_frame_count)?
            .absorb(Maybe::new(hdf.linked_msg_address.as_ref()))?
            .mask(&hdf.publisher)?
            .skip(Size::new(hdf.sequence))?;

        Ok(self)
    }
}

#[async_trait(?Send)]
impl<F, IS, Address> ContentUnwrap<HDF<Address>> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
    for<'a> unwrap::Context<IS, F>: Absorb<&'a mut Address> + Absorb<&'a mut Uint8>,
    Address: Default,
{
    async fn unwrap(&mut self, mut hdf: &mut HDF<Address>) -> Result<&mut Self> {
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
                version.inner() == STREAMS_1_VER,
                anyhow!("Msg version '{}' not supported", version),
            )?
            .skip(&mut message_type_and_payload_length)?
            .guard(
                0 == message_type_and_payload_length[0] & 0b1100,
                anyhow!("bits 5 and 6 between content-type and payload-length are reserved"),
            )?
            .absorb(External::new(Uint8::new(
                // Absorb only message_type
                message_type_and_payload_length[0] & 0b11110000,
            )))?
            .absorb(&mut frame_type)?
            .guard(
                frame_type.inner() == HDF_ID,
                anyhow!("Invalid message type. Found '{}', expected '{}'", frame_type, HDF_ID),
            )?
            .skip(&mut payload_frame_count_bytes)?
            .guard(
                0 == payload_frame_count_bytes[0] & 0b1100,
                anyhow!("first 2 bits of payload-frame-count are reserved"),
            )?
            .absorb(Maybe::new(&mut hdf.linked_msg_address))?
            .mask(&mut hdf.publisher)?
            .skip(&mut seq_num)?;

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
