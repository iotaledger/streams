use alloc::boxed::Box;
use core::fmt;

use anyhow::{
    anyhow,
    ensure,
    Result,
};
use async_trait::async_trait;

use crypto::signatures::ed25519;

// TODO: REMOVE
// use iota_streams_core::{
//     async_trait,
//     prelude::Box,
//     sponge::prp::PRP,
//     try_or,
//     Errors::*,
//     Result,
// };

use spongos::{
    ddml::{
        commands::{
            sizeof,
            unwrap,
            wrap,
            Absorb,
            Guard,
            Skip,
        },
        io,
        modifiers::External,
        types::{
            NBytes,
            Uint64,
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

const FLAG_BRANCHING_MASK: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub struct HDF<Address> {
    // address: Address,
    encoding: u8,
    version: u8,
    // content type is 4 bits
    message_type: u8,
    // payload length is 10 bits
    payload_length: u16,
    frame_type: u8,
    // frame count is 22 bits
    payload_frame_count: u32,
    linked_msg_address: Option<Address>,
    sequence: u64,
    // sender_id: Identifier,
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
        }
    }
}

impl<Address> HDF<Address> {
    pub fn new(message_type: u8, seq_num: u64) -> Result<Self> {
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
            sequence: seq_num,
        })
    }

    // TODO: REMOVE
    // pub(crate) fn with_address(mut self, address: Address) -> Self {
    //     self.address = address;
    //     self
    // }

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

    // TODO: REMOVE
    // fn with_content_type(mut self, content_type: u8) -> Result<Self> {
    //     try_or!(content_type < 0x10, ValueOutOfRange(0x10_usize, content_type as usize))?;
    //     self.content_type = content_type;
    //     Ok(self)
    // }
    // fn with_payload_length(mut self, payload_length: usize) -> Result<Self> {
    //     try_or!(payload_length < 0x0400, MaxSizeExceeded(0x0400_usize, payload_length))?;
    //     self.payload_length = payload_length;
    //     Ok(self)
    // }
    // fn with_payload_frame_count(mut self, payload_frame_count: u32) -> Result<Self> {
    //     try_or!(
    //         payload_frame_count < 0x400000,
    //         MaxSizeExceeded(0x400000_usize, payload_frame_count as usize)
    //     )?;
    //     self.payload_frame_count = payload_frame_count;
    //     Ok(self)
    // }
    // fn with_seq_num(mut self, seq_num: u32) -> Self {
    //     self.seq_num = Uint64(seq_num as u64);
    //     self
    // }
    // fn with_identifier(mut self, id: &Identifier) -> Self {
    //     self.sender_id = *id;
    //     self
    // }
    // fn with_previous_msg_link(mut self, previous_msg_link: Bytes) -> Self {
    //     self.previous_msg_link = previous_msg_link;
    //     self
    // }

    pub(crate) fn message_type(&self) -> u8 {
        self.message_type
    }

    fn payload_length(&self) -> u16 {
        self.payload_length
    }

    fn payload_frame_count(&self) -> u32 {
        self.payload_frame_count
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    // fn identifier(&self) -> &Identifier {
    //     &self.sender_id
    // }

    pub(crate) fn linked_msg_address(&self) -> &Option<Address> {
        &self.linked_msg_address
    }

    // pub fn address(&self) -> &Address {
    //     &self.address
    // }
}

// impl<Link> fmt::Debug for HDF<Link>
// where
//     Link: fmt::Debug,
// {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(
//             f,
//             "{{encoding: {:?}, version: {:?}, content_type: {:?}, payload_length: {:?}}}",
//             self.encoding,
//             self.version,
//             self.content_type(),
//             self.payload_length()
//         )
//     }
// }

// TODO: REVIEW IF WE CAN GET RID OF THE MULTIPLE BOUNDS BY USING for <'a>
#[async_trait(?Send)]
impl<Link> ContentSizeof<HDF<Link>> for sizeof::Context
where
    // sizeof::Context<F>: Absorb<Link> + Absorb<Uint8> +
    // Absorb<External<Link>>,
    for<'a> Self: Absorb<&'a Link> + Absorb<&'a ()>,
{
    async fn sizeof(&mut self, hdf: &HDF<Link>) -> Result<&mut Self> {
        let message_type_and_payload_length = NBytes::<[u8; 2]>::default();
        let payload_frame_count = NBytes::<[u8; 3]>::default();
        self.absorb(Uint8::new(hdf.encoding))?
            .absorb(Uint8::new(hdf.version))?
            .skip(&message_type_and_payload_length)?
            .absorb(External::new(Uint8::new(hdf.message_type << 4)))? // ?
            .absorb(Uint8::new(hdf.frame_type))?
            .skip(&payload_frame_count)?
            // .absorb(External::new(&hdf.address))?
            .absorb(hdf.linked_msg_address.as_ref())?
            .skip(Uint64::new(hdf.sequence))?;
        // .sizeof(&hdf.sender_id)
        // .await?;

        Ok(self)
    }
}

#[async_trait(?Send)]
impl<F, OS, Link> ContentWrap<HDF<Link>> for wrap::Context<F, OS>
where
    F: PRP,
    OS: io::OStream,
    Self: for<'a> Absorb<&'a Link> + Absorb<Uint8>,
{
    async fn wrap(&mut self, hdf: &mut HDF<Link>) -> Result<&mut Self> {
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
            // .absorb(External::new(&hdf.address))?
            .absorb(hdf.linked_msg_address.as_ref())?
            .skip(Uint64::new(hdf.sequence))?;
        // .wrap(&mut hdf.sender_id)
        // .await?;

        Ok(self)
    }
}

// #[async_trait(?Send)]
// impl<F, OS, Link> ContentWrap<HDF<Link>> for wrap::Context<F, OS>
// where
//     F: PRP,
//     OS: io::OStream,
//     wrap::Context<F, OS>: for<'a> Absorb<&'a Link> + for <'a> Absorb<External<&'a Link>>,
//     sizeof::Context: for<'a> Absorb<&'a Link> + for <'a> Absorb<External<&'a Link>>,
// {
//     async fn wrap<'b>(&mut self, ctx: &'b mut wrap::Context<F, OS>) -> Result<&'b mut wrap::Context<F, OS>> {
//         let content_type_and_payload_length = {
//             let mut nbytes = NBytes::<[u8; 2]>::default();
//             nbytes[0] = (self.content_type << 4) | ((self.payload_length >> 8) as u8 & 0b0011);
//             nbytes[1] = self.payload_length as u8;
//             nbytes
//         };
//         let payload_frame_count = {
//             let mut nbytes = NBytes::<[u8; 3]>::default();
//             let x = self.payload_frame_count.to_be_bytes();
//             nbytes[0] = x[1] & 0b00111111;
//             nbytes[1] = x[2];
//             nbytes[2] = x[3];
//             nbytes
//         };

//         ctx.absorb(Uint8::new(self.encoding))?
//             .absorb(Uint8::new(self.version))?
//             .skip(&content_type_and_payload_length)?
//             .absorb(External::new(Uint8::new(self.content_type << 4)))?
//             .absorb(Uint8::new(self.frame_type))?
//             .skip(&payload_frame_count)?
//             .absorb(External::new(&self.address))?
//             .absorb(&self.previous_msg_address)?
//             .skip(Uint64::new(self.seq_num))?;

//         self.sender_id.wrap(ctx).await?;

//         Ok(ctx)
//     }
// }

#[async_trait(?Send)]
impl<F, IS, Address> ContentUnwrap<HDF<Address>> for unwrap::Context<F, IS>
where
    F: PRP,
    IS: io::IStream,
    // TODO: Investigate how to get rid of this hack (necessary because of trait recursion)
    for<'a> unwrap::Context<F, IS>: Absorb<&'a mut Address> + Absorb<&'a mut Option<Address>>,
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
        let mut seq_num = Uint64::default();

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
            // .absorb(External::new(&hdf.address))?
            .absorb(&mut hdf.linked_msg_address)?
            .skip(&mut seq_num)?;
        // .unwrap(&mut hdf.sender_id)
        // .await?;

        hdf.encoding = encoding.inner();
        hdf.version = version.inner();
        hdf.message_type = message_type_and_payload_length[0] >> 4;
        hdf.payload_length =
            (((message_type_and_payload_length[0] & 0b0011) as u16) << 8) | (message_type_and_payload_length[1] as u16);
        hdf.frame_type = frame_type.inner();

        let mut x = [0_u8; 4];
        x[1] = payload_frame_count_bytes[0];
        x[2] = payload_frame_count_bytes[1];
        x[3] = payload_frame_count_bytes[2];
        hdf.payload_frame_count = u32::from_be_bytes(x);

        hdf.sequence = seq_num.inner();

        Ok(self)
    }
}
