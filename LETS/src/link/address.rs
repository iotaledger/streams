// Rust
use alloc::string::String;
use core::{
    convert::TryInto,
    fmt::{
        self,
        Debug,
        Display,
        Formatter,
        LowerHex,
        UpperHex,
    },
    marker::PhantomData,
    str::FromStr,
};

// 3rd-party
use anyhow::{
    anyhow,
    Result,
};

// IOTA
use crypto::hashes::{
    blake2b::Blake2b256,
    Digest,
};

// Streams
use spongos::{
    Spongos,
    PRP,
};

// Local
use crate::{
    id::Identifier,
    link::{
        cursor::Cursor,
        link::{
            Link,
            LinkGenerator,
        },
    },
};

/// Tangle representation of a Message Link
///
/// A `TangleAddress` is comprised of 2 distinct parts: the channel identifier
/// ([`TangleAddress::appinst`]) and the message identifier
/// ([`TangleAddress::msgid`]). The channel identifier, also refered to as
/// the channel address, is unique per channel and is common in the
/// `TangleAddress` of all messages published in it. The message identifier is
/// produced pseudo-randomly out of the the message's sequence number, the
/// previous message identifier, and other internal properties.
///
/// ## Renderings
/// ### Blake2b hash
/// A `TangleAddress` is used as index of the message over the Tangle. For that,
/// its content is hashed using [`TangleAddress::to_msg_index()`]. If the binary
/// digest of the hash needs to be encoded in hexadecimal, you can use
/// [`core::LowerHex`] or [`core::UpperHex`]:
///
/// ```
/// # use iota_streams_app::transport::tangle::TangleAddress;
/// # use iota_streams_ddml::types::NBytes;
/// #
/// # fn main() -> anyhow::Result<()> {
/// let address = TangleAddress::new([172_u8; 40][..].into(), [171_u8; 12][..].into());
/// assert_eq!(
///     address.to_msg_index().as_ref(),
///     &[
///         44, 181, 155, 1, 109, 141, 169, 177, 209, 70, 226, 18, 190, 121, 40, 44, 90, 108, 159, 109, 241, 37, 30, 0,
///         185, 80, 245, 59, 235, 75, 128, 97
///     ],
/// );
/// assert_eq!(
///     format!("{:x}", address.to_msg_index()),
///     "2cb59b016d8da9b1d146e212be79282c5a6c9f6df1251e00b950f53beb4b8061".to_string()
/// );
/// #   Ok(())
/// # }
/// ```
///
/// ### exchangeable encoding
/// In order to exchange a `TangleAddress` between channel participants, it can be encoded and decoded
/// using [`TangleAddress::to_string()`][Display] (or [`format!()`]) and [`TangleAddress::from_str`] (or
/// [`str::parse()`]). This method encodes the `TangleAddress` as a colon-separated string containing the `appinst` and
/// `msgid` in hexadecimal:
/// ```
/// # use iota_streams_app::transport::tangle::TangleAddress;
/// # use iota_streams_ddml::types::NBytes;
/// #
/// # fn main() -> anyhow::Result<()> {
/// let address = TangleAddress::new([170_u8; 40][..].into(), [255_u8; 12][..].into());
/// let address_str = address.to_string();
/// assert_eq!(
///     address_str,
///     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:ffffffffffffffffffffffff"
///         .to_string(),
/// );
/// assert_eq!(address_str.parse::<TangleAddress>()?, address);
/// #   Ok(())
/// # }
/// ```
///
/// ## Debugging
///
/// For debugging purposes, `TangleAddress` implements `Debug`, which can be triggered with the formatting `{:?}`
/// or the pretty-printed `{:#?}`. These will output `appinst` and `msgid` as decimal arrays; you can also use
/// `{:x?}` or `{:#x?}` to render them as hexadecimal arrays.
///
/// [Display]: #impl-Display
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default, Hash)]
pub struct Address {
    appaddr: AppAddr,
    msgid: MsgId,
}

impl Address {
    fn new(appaddr: AppAddr, msgid: MsgId) -> Self {
        Self { appaddr, msgid }
    }

    /// Hash the content of the [`Address`] using `Blake2b256`
    pub(crate) fn to_blake2b(self) -> [u8; 32] {
        let hasher = Blake2b256::new();
        hasher.chain(&self.appaddr).chain(&self.msgid).finalize().into()
    }

    // TODO: REMOVE
    // /// Generate the hash used to index the [`TangleMessage`] published in this address
    // ///
    // /// Currently this hash is computed with [Blake2b256].
    // ///
    // /// [Blake2b256]: https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2|Blake2b256
    // fn to_msg_index(self) -> NBytes<U32> {
    //     self.to_blake2b()
    // }

    // TODO: REMOVE
    // /// # Safety
    // ///
    // /// This function uses CStr::from_ptr which is unsafe...
    // unsafe fn from_c_str(c_addr: *const c_char) -> *const Self {
    //     c_addr.as_ref().map_or(null(), |c_addr| {
    //         CStr::from_ptr(c_addr).to_str().map_or(null(), |addr_str| {
    //             Self::from_str(addr_str).map_or(null(), |addr| Box::into_raw(Box::new(addr)))
    //         })
    //     })
    // }
}

/// String representation of a Tangle Link
///
/// The current string representation of a Tangle Link is the
/// colon-separated conjunction of the hex-encoded `appinst` and `msgid`:
/// `"<appinst>:<msgid>"`.
impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}:{:x}", self.appaddr, self.msgid)
    }
}

/// Create a TangleAddress out of it's string representation
///
/// This method is the opposite of [`TangleAddress::to_string()`][`Display`]
/// (see [`Display`]): it expects a colon-separated string containing the
/// hex-encoded `appinst` and `msgid`.
///
/// [`Display`]: #impl-Display
impl FromStr for Address {
    type Err = anyhow::Error;
    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let (appinst_str, msgid_str) = string.split_once(':').ok_or_else(|| {
            anyhow!("Malformed address string: missing colon (':') separator between appinst and msgid")
        })?;
        let appaddr = AppAddr::from_str(appinst_str).map_err(|e| {
            anyhow!(
                "AppAddr is not encoded in hexadecimal or the encoding is incorrect: {}",
                e
            )
        })?;

        let msgid = MsgId::from_str(msgid_str).map_err(|e| {
            anyhow!(
                "MsgId is not encoded in hexadecimal or the encoding is incorrect: {}",
                e
            )
        })?;

        Ok(Address { appaddr, msgid })
    }
}

impl Link for Address {
    type Base = AppAddr;
    type Relative = MsgId;

    fn base(&self) -> &AppAddr {
        &self.appaddr
    }

    fn into_base(self) -> AppAddr {
        self.appaddr
    }

    fn relative(&self) -> &MsgId {
        &self.msgid
    }

    fn into_relative(self) -> MsgId {
        self.msgid
    }

    fn from_parts(appaddr: AppAddr, msgid: MsgId) -> Self {
        Self::new(appaddr, msgid)
    }

    // TODO: REMOVE
    // fn from_base_rel(base: &AppAddr, rel: &MsgId) -> Self {
    //     Self {
    //         appaddr: *base,
    //         msgid: *rel,
    //     }
    // }
    // fn to_bytes(&self) -> Vec<u8> {
    //     let mut bytes = self.appaddr.as_ref().to_vec();
    //     bytes.extend_from_slice(self.msgid.as_ref());
    //     bytes
    // }

    // fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
    //     if bytes.len() != APPINST_SIZE + MSGID_SIZE {
    //         return err!(InvalidMessageAddress);
    //     }
    //     Ok(Address::new(
    //         AppAddr::from(&bytes[0..APPINST_SIZE]),
    //         MsgId::from(&bytes[APPINST_SIZE..]),
    //     ))
    // }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
struct AddressGenerator<F>(PhantomData<F>);

impl<'a, F> LinkGenerator<'a, MsgId> for AddressGenerator<F>
where
    F: Default + PRP,
{
    type Data = (&'a AppAddr, Identifier, u64);

    // fn init(appaddr: AppAddr) -> Self {
    //     Self {
    //         appaddr,
    //         f: PhantomData,
    //     }
    // }

    fn gen(&mut self, (appaddr, identifier, seq_num): (&'a AppAddr, Identifier, u64)) -> MsgId {
        let mut s = Spongos::<F>::init();
        s.absorb(appaddr);
        s.absorb(identifier);
        s.absorb(seq_num.to_be_bytes());
        s.commit();
        s.squeeze()
    }
}

impl<F> LinkGenerator<'_, AppAddr> for AddressGenerator<F>
{
    type Data = (Identifier, u64);

    fn gen(&mut self, (identifier, channel_idx): (Identifier, u64)) -> AppAddr {
        AppAddr::new(identifier, channel_idx)
    }
}

// impl<F> Default for DefaultTangleLinkGenerator<F> {
//     fn default() -> Self {
//         Self {
//             addr: Address::default(),
//             _phantom: core::marker::PhantomData,
//         }
//     }
// }

// impl<F> DefaultTangleLinkGenerator<F> {
//     fn reset_addr(&mut self, addr: Address) {
//         self.addr = addr;
//     }
// }

// impl<F: PRP> DefaultTangleLinkGenerator<F> {
//     fn gen_uniform_msgid(&self, cursor: Cursor<&MsgId>) -> MsgId {
//         let mut s = Spongos::<F>::init();
//         s.absorb(self.addr.appaddr.id.as_ref());
//         s.absorb(cursor.link.id.as_ref());
//         s.absorb(&cursor.branch_no.to_be_bytes());
//         s.absorb(&cursor.seq_no.to_be_bytes());
//         s.commit();
//         let mut new = MsgId::default();
//         s.squeeze(new.id.as_mut());
//         new
//     }
//     fn gen_msgid(&self, id_bytes: &[u8], cursor: Cursor<&MsgId>) -> MsgId {
//         let mut s = Spongos::<F>::init();
//         s.absorb(self.addr.appaddr.id.as_ref());
//         s.absorb(id_bytes);
//         s.absorb(cursor.link.id.as_ref());
//         s.absorb(&cursor.branch_no.to_be_bytes());
//         s.absorb(&cursor.seq_no.to_be_bytes());
//         s.commit();
//         let mut new = MsgId::default();
//         s.squeeze(new.id.as_mut());
//         new
//     }
// }

// impl<F: PRP> LinkGenerator<Address> for DefaultTangleLinkGenerator<F> {
//     /// Used by Author to generate a new application instance: channels address and announcement message identifier
//     fn gen(&mut self, id: &Identifier, channel_idx: u64) {
//         self.addr.appaddr = AppAddr::new(id, channel_idx);
//         self.addr.msgid = self.gen_msgid(id.as_ref(), Cursor::default().as_ref());
//     }

//     /// Used by Author to get announcement message id, it's just stored internally by link generator
//     fn get(&self) -> Address {
//         self.addr
//     }

//     /// Used by Subscriber to initialize link generator with the same state as Author
//     fn reset(&mut self, announcement_link: Address) {
//         self.addr = announcement_link;
//     }

//     /// Used by users to pseudo-randomly generate a new uniform message link from a cursor
//     fn uniform_link_from(&self, cursor: Cursor<&MsgId>) -> Address {
//         Address {
//             appaddr: self.addr.appaddr,
//             msgid: self.gen_uniform_msgid(cursor),
//         }
//     }

//     /// Used by users to pseudo-randomly generate a new message link from a cursor
//     fn link_from<T: AsRef<[u8]>>(&self, id: T, cursor: Cursor<&MsgId>) -> Address {
//         Address {
//             appaddr: self.addr.appaddr,
//             msgid: self.gen_msgid(id.as_ref(), cursor),
//         }
//     }
// }

// TODO: REMOVE
// type AppInstSize = U40;
// const APPINST_SIZE: usize = 40;

/// 40 byte Application Instance identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AppAddr([u8; Self::SIZE]);

impl AppAddr {
    const SIZE: usize = 40;

    pub fn new(id: Identifier, channel_idx: u64) -> Self {
        let mut addr = [0_u8; 40];
        let id_bytes = id.as_bytes();
        assert_eq!(id_bytes.len(), 32, "identifier must be 32 bytes long");
        addr[..32].copy_from_slice(id_bytes);
        addr[32..].copy_from_slice(&channel_idx.to_be_bytes());
        Self(addr)
    }

    /// Get the hexadecimal representation of the AppInst
    fn to_hex_string(&self) -> String {
        hex::encode(self.0)
    }

    /// Get a view into the internal byte array that constitutes an `AppInst`
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Default for AppAddr {
    fn default() -> Self {
        Self([0; 40])
    }
}

// TODO: REMOVE
// impl<'a> From<&'a [u8]> for AppAddr {
//     fn from(v: &[u8]) -> AppAddr {
//         AppAddr {
//             // TODO: Implement safer TryFrom or force check for length at call site.
//             id: *<&NBytes<AppInstSize>>::from(v),
//         }
//     }
// }

impl FromStr for AppAddr {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let appaddr_bin = hex::decode(s)?;
        appaddr_bin.try_into().map(Self).map_err(|e| {
            anyhow!(
                "AppAddr must be {} bytes long, but is {} bytes long instead",
                Self::SIZE,
                e.len()
            )
        })
    }
}

/// Display AppInst with its hexadecimal representation (lower case)
impl Display for AppAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl LowerHex for AppAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex_string())
    }
}

impl UpperHex for AppAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode_upper(self.0))
    }
}

impl AsRef<[u8]> for AppAddr {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

// TODO: REMOVE
// type MsgIdSize = U12;
/// Unique 12 byte identifier
// const MSGID_SIZE: usize = 12;

/// 12 byte Message Identifier unique within the same application.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Hash)]
pub struct MsgId([u8; Self::SIZE]);

impl MsgId {
    const SIZE: usize = 12;

    /// Get the hexadecimal representation of the MsgId
    fn to_hex_string(&self) -> String {
        hex::encode(self.0)
    }

    /// Get a view into the internal byte array that constitutes an `MsgId`
    fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

// TODO: REMOVE
// impl<'a> From<&'a [u8]> for MsgId {
//     fn from(v: &[u8]) -> MsgId {
//         MsgId (
//     }
// }

impl FromStr for MsgId {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let msgid_bin = hex::decode(s)?;
        msgid_bin.try_into().map(Self).map_err(|e| {
            anyhow!(
                "MsgId must be {} bytes long, but is {} bytes long instead",
                Self::SIZE,
                e.len()
            )
        })
    }
}

// TODO: REMOVE
// impl From<NBytes<MsgIdSize>> for MsgId {
//     fn from(b: NBytes<MsgIdSize>) -> Self {
//         Self { id: b }
//     }
// }

/// Display MsgId with its hexadecimal representation (lower case)
impl Display for MsgId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl LowerHex for MsgId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex_string())
    }
}

impl UpperHex for MsgId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode_upper(self.0))
    }
}

impl AsRef<[u8]> for MsgId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for MsgId {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
