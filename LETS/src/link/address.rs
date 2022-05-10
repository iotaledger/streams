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
    ddml::{
        commands::{
            sizeof,
            unwrap,
            wrap,
            Absorb,
            Mask,
        },
        io,
        types::NBytes,
    },
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
/// let address = TangleAddress::new([172u8; 40][..].into(), [171u8; 12][..].into());
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
/// let address = TangleAddress::new([170u8; 40][..].into(), [255u8; 12][..].into());
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct Address {
    appaddr: AppAddr,
    msgid: MsgId,
}

impl Address {
    fn new(appaddr: AppAddr, msgid: MsgId) -> Self {
        Self { appaddr, msgid }
    }

    /// Hash the content of the [`Address`] using `Blake2b256`
    pub fn to_blake2b(self) -> [u8; 32] {
        let hasher = Blake2b256::new();
        hasher.chain(&self.appaddr).chain(&self.msgid).finalize().into()
    }

    pub fn to_msg_index(self) -> [u8; 32] {
        self.to_blake2b()
    }

    pub fn relative(self) -> MsgId {
        self.msgid
    }

    pub fn base(self) -> AppAddr {
        self.appaddr
    }
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
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Default)]
pub struct AddressGenerator<F>(PhantomData<F>);

impl<'a, F> LinkGenerator<'a, MsgId> for AddressGenerator<F>
where
    F: Default + PRP,
{
    type Data = (&'a AppAddr, Identifier, usize);

    fn gen(&mut self, (appaddr, identifier, seq_num): (&'a AppAddr, Identifier, usize)) -> MsgId {
        let mut s = Spongos::<F>::init();
        s.absorb(appaddr);
        s.absorb(identifier);
        s.absorb(seq_num.to_be_bytes());
        s.commit();
        s.squeeze()
    }
}

impl<F> LinkGenerator<'_, AppAddr> for AddressGenerator<F> {
    type Data = (Identifier, usize);

    fn gen(&mut self, (identifier, channel_idx): (Identifier, usize)) -> AppAddr {
        AppAddr::new(identifier, channel_idx as u64)
    }
}

/// 40 byte Application Instance identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AppAddr([u8; Self::SIZE]);

impl AppAddr {
    const SIZE: usize = 40;

    pub fn new(id: Identifier, channel_idx: u64) -> Self {
        let mut addr = [0u8; 40];
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

impl AsMut<[u8]> for AppAddr {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

/// 12 byte Message Identifier unique within the same application.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

impl<'a> Absorb<&'a MsgId> for sizeof::Context {
    fn absorb(&mut self, msgid: &'a MsgId) -> Result<&mut Self> {
        self.absorb(NBytes::new(msgid))
    }
}

impl<'a, F, OS> Absorb<&'a MsgId> for wrap::Context<F, OS>
where
    F: PRP,
    OS: io::OStream,
{
    fn absorb(&mut self, msgid: &'a MsgId) -> Result<&mut Self> {
        self.absorb(NBytes::new(msgid))
    }
}

impl<'a, F, IS> Absorb<&'a mut MsgId> for unwrap::Context<F, IS>
where
    F: PRP,
    IS: io::IStream,
{
    fn absorb(&mut self, msgid: &'a mut MsgId) -> Result<&mut Self> {
        self.absorb(NBytes::new(msgid))
    }
}

impl<'a> Absorb<&'a AppAddr> for sizeof::Context {
    fn absorb(&mut self, appaddr: &'a AppAddr) -> Result<&mut Self> {
        self.absorb(NBytes::new(appaddr))
    }
}

impl<'a, F, OS> Absorb<&'a AppAddr> for wrap::Context<F, OS>
where
    F: PRP,
    OS: io::OStream,
{
    fn absorb(&mut self, appaddr: &'a AppAddr) -> Result<&mut Self> {
        self.absorb(NBytes::new(appaddr))
    }
}

impl<'a, F, IS> Absorb<&'a mut AppAddr> for unwrap::Context<F, IS>
where
    F: PRP,
    IS: io::IStream,
{
    fn absorb(&mut self, appaddr: &'a mut AppAddr) -> Result<&mut Self> {
        self.absorb(NBytes::new(appaddr))
    }
}

impl<'a> Absorb<&'a Address> for sizeof::Context {
    fn absorb(&mut self, address: &'a Address) -> Result<&mut Self> {
        self.absorb(&address.appaddr)?.absorb(&address.msgid)
    }
}

impl<'a, F, OS> Absorb<&'a Address> for wrap::Context<F, OS>
where
    F: PRP,
    OS: io::OStream,
{
    fn absorb(&mut self, address: &'a Address) -> Result<&mut Self> {
        self.absorb(&address.appaddr)?.absorb(&address.msgid)
    }
}

impl<'a, F, IS> Absorb<&'a mut Address> for unwrap::Context<F, IS>
where
    F: PRP,
    IS: io::IStream,
{
    fn absorb(&mut self, address: &'a mut Address) -> Result<&mut Self> {
        self.absorb(&mut address.appaddr)?.absorb(&mut address.msgid)
    }
}

impl<'a> Mask<&'a MsgId> for sizeof::Context {
    fn mask(&mut self, msgid: &'a MsgId) -> Result<&mut Self> {
        self.mask(NBytes::new(msgid))
    }
}

impl<'a, F, OS> Mask<&'a MsgId> for wrap::Context<F, OS>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, msgid: &'a MsgId) -> Result<&mut Self> {
        self.mask(NBytes::new(msgid))
    }
}

impl<'a, F, IS> Mask<&'a mut MsgId> for unwrap::Context<F, IS>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, msgid: &'a mut MsgId) -> Result<&mut Self> {
        self.mask(NBytes::new(msgid))
    }
}

impl<'a> Mask<&'a AppAddr> for sizeof::Context {
    fn mask(&mut self, appaddr: &'a AppAddr) -> Result<&mut Self> {
        self.mask(NBytes::new(appaddr))
    }
}

impl<'a, F, OS> Mask<&'a AppAddr> for wrap::Context<F, OS>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, appaddr: &'a AppAddr) -> Result<&mut Self> {
        self.mask(NBytes::new(appaddr))
    }
}

impl<'a, F, IS> Mask<&'a mut AppAddr> for unwrap::Context<F, IS>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, appaddr: &'a mut AppAddr) -> Result<&mut Self> {
        self.mask(NBytes::new(appaddr))
    }
}

impl<'a> Mask<&'a Address> for sizeof::Context {
    fn mask(&mut self, address: &'a Address) -> Result<&mut Self> {
        self.mask(&address.appaddr)?.mask(&address.msgid)
    }
}

impl<'a, F, OS> Mask<&'a Address> for wrap::Context<F, OS>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, address: &'a Address) -> Result<&mut Self> {
        self.mask(&address.appaddr)?.mask(&address.msgid)
    }
}

impl<'a, F, IS> Mask<&'a mut Address> for unwrap::Context<F, IS>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, address: &'a mut Address) -> Result<&mut Self> {
        self.mask(&mut address.appaddr)?.mask(&mut address.msgid)
    }
}
