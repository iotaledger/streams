// Rust
use alloc::{
    boxed::Box,
    string::{String, ToString},
};
use core::{
    convert::TryInto,
    fmt::{self, Debug, Display, Formatter, LowerHex, UpperHex},
    str::FromStr,
};

use serde_big_array::BigArray;

// IOTA
use crypto::hashes::{blake2b::Blake2b256, Digest};

// Streams
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Absorb, Mask},
        io,
        types::NBytes,
    },
    error::Result as SpongosResult,
    KeccakF1600, Spongos, PRP,
};

// Local
use crate::{
    error::{Error, Result},
    id::Identifier,
    message::Topic,
};

/// Abstract representation of a Message Address
///
/// An `Address` is comprised of 2 distinct parts: the [application address](`AppAddr`)
/// and the [message identifier](`MsgId`). The application address is unique per application
/// and is common in the `Address` of all messages published in it. The message identifier
/// is produced pseudo-randomly out of the publisher's identifier and the message's sequence
/// number
///
/// ## exchangeable encoding
/// In order to exchange an `Address` between application participants, it can be encoded and
/// decoded using [`Address::to_string()`][Display] (or [`format!()`]) and [`Address::from_str`] (or
/// [`str::parse()`]). This method encodes the `Address` as a colon-separated string containing the
/// `appaddr` and `msgid` in hexadecimal:
/// ```
/// # use lets::address::Address;
/// #
/// # fn main() -> anyhow::Result<()> {
/// let address = Address::new([170; 40], [255; 12]);
/// let address_str = address.to_string();
/// assert_eq!(
///     address_str,
///     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:ffffffffffffffffffffffff"
///         .to_string(),
/// );
/// assert_eq!(address_str.parse::<Address>().map_err(|e| anyhow::anyhow!(e.to_string()))?, address);
/// #   Ok(())
/// # }
/// ```
///
/// ## Debugging
///
/// For debugging purposes, `Address` implements `Debug`, which can be triggered with the formatting
/// `{:?}` or the pretty-printed `{:#?}`. These will output `appaddr` and `msgid` as decimal arrays;
/// you can also use `{:x?}` or `{:#x?}` to render them as hexadecimal arrays.
///
/// [Display]: #impl-Display
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Hash, serde::Serialize)]
pub struct Address {
    /// The base address of the application
    appaddr: AppAddr,
    /// The message ID of a specific message
    msgid: MsgId,
}

impl Address {
    /// Creates a new `Address` from an `AppAddr` and a `MsgId`
    ///
    /// # Arguments
    /// * `appaddr`: The base address of the application.
    /// * `msgid`: The unique message ID
    pub fn new<A, M>(appaddr: A, msgid: M) -> Self
    where
        A: Into<AppAddr>,
        M: Into<MsgId>,
    {
        Self {
            appaddr: appaddr.into(),
            msgid: msgid.into(),
        }
    }

    /// Returns the address [Message Id](`MsgId`)
    pub fn relative(self) -> MsgId {
        self.msgid
    }

    /// Returns the [Application Address](`AppAddr`)
    pub fn base(self) -> AppAddr {
        self.appaddr
    }

    /// Hash the content of the [`Address`] using `Blake2b256`
    pub fn to_blake2b(self) -> [u8; 32] {
        let hasher = Blake2b256::new();
        hasher.chain(self.base()).chain(self.relative()).finalize().into()
    }

    /// Hash the content of the [`Address`] using `Blake2b256`
    pub fn to_msg_index(self) -> [u8; 32] {
        self.to_blake2b()
    }
}

/// String representation of a Tangle Link
///
/// The current string representation of a Tangle Link is the
/// colon-separated conjunction of the hex-encoded `appaddr` and `msgid`:
/// `"<appaddr>:<msgid>"`.
impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}:{:x}", self.appaddr, self.msgid)
    }
}

/// Create a Address out of it's string representation
///
/// This method is the opposite of [`Address::to_string()`][`Display`]
/// (see [`Display`]): it expects a colon-separated string containing the
/// hex-encoded `appaddr` and `msgid`.
///
/// [`Display`]: #impl-Display
impl FromStr for Address {
    type Err = crate::error::Error;
    fn from_str(string: &str) -> Result<Address> {
        let (appaddr_str, msgid_str) =
            string
                .split_once(':')
                .ok_or(Error::Malformed("address string", ":", string.to_string()))?;
        let appaddr =
            AppAddr::from_str(appaddr_str).map_err(|e| Error::Encoding("AppAddr", "hexadecimal", Box::new(e)))?;

        let msgid = MsgId::from_str(msgid_str).map_err(|e| Error::Encoding("MsgId", "hexadecimal", Box::new(e)))?;

        Ok(Address { appaddr, msgid })
    }
}

/// 40 byte Application Instance identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]

pub struct AppAddr(#[serde(with = "BigArray")] [u8; Self::SIZE]);

impl AppAddr {
    const SIZE: usize = 40;

    pub fn new(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }

    pub fn gen(identifier: &Identifier, base_topic: &Topic) -> AppAddr {
        let mut spongos = Spongos::<KeccakF1600>::init();
        spongos.absorb(base_topic);
        spongos.absorb(identifier);
        spongos.commit();
        spongos.squeeze()
    }

    /// Get the hexadecimal representation of the appaddr
    pub fn to_hex_string(self) -> String {
        hex::encode(self.0)
    }

    /// Get a view into the internal byte array that constitutes an [`AppAddr`]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Default for AppAddr {
    fn default() -> Self {
        Self([0; 40])
    }
}

impl FromStr for AppAddr {
    type Err = crate::error::Error;
    fn from_str(s: &str) -> Result<Self> {
        let appaddr_bin = hex::decode(s)?;
        appaddr_bin
            .try_into()
            .map(Self)
            .map_err(|e| Error::InvalidSize("AppAddr", Self::SIZE, e.len().try_into().unwrap()))
    }
}

/// Display appaddr with its hexadecimal representation (lower case)
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

impl From<[u8; 40]> for AppAddr {
    fn from(array: [u8; 40]) -> Self {
        Self(array)
    }
}

/// 12 byte Message Identifier unique within the same application.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct MsgId([u8; Self::SIZE]);

impl MsgId {
    const SIZE: usize = 12;

    pub fn new(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }

    pub fn gen(appaddr: AppAddr, identifier: &Identifier, topic: &Topic, seq_num: usize) -> MsgId {
        let mut s = Spongos::<KeccakF1600>::init();
        s.absorb(appaddr);
        s.absorb(identifier);
        s.absorb(topic);
        s.absorb(seq_num.to_be_bytes());
        s.commit();
        s.squeeze()
    }

    /// Get the hexadecimal representation of the MsgId
    fn to_hex_string(self) -> String {
        hex::encode(self.0)
    }

    /// Get a view into the internal byte array that constitutes an `MsgId`
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl FromStr for MsgId {
    type Err = crate::error::Error;
    fn from_str(s: &str) -> Result<Self> {
        let msgid_bin = hex::decode(s)?;
        msgid_bin
            .try_into()
            .map(Self)
            .map_err(|e| Error::InvalidSize("MsgId", Self::SIZE, e.len().try_into().unwrap()))
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

impl From<[u8; 12]> for MsgId {
    fn from(array: [u8; 12]) -> Self {
        Self(array)
    }
}

impl Absorb<&MsgId> for sizeof::Context {
    fn absorb(&mut self, msgid: &MsgId) -> SpongosResult<&mut Self> {
        self.absorb(NBytes::new(msgid))
    }
}

impl<OS, F> Absorb<&MsgId> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn absorb(&mut self, msgid: &MsgId) -> SpongosResult<&mut Self> {
        self.absorb(NBytes::new(msgid))
    }
}

impl<IS, F> Absorb<&mut MsgId> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn absorb(&mut self, msgid: &mut MsgId) -> SpongosResult<&mut Self> {
        self.absorb(NBytes::new(msgid))
    }
}

impl Absorb<&AppAddr> for sizeof::Context {
    fn absorb(&mut self, appaddr: &AppAddr) -> SpongosResult<&mut Self> {
        self.absorb(NBytes::new(appaddr))
    }
}

impl<OS, F> Absorb<&AppAddr> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn absorb(&mut self, appaddr: &AppAddr) -> SpongosResult<&mut Self> {
        self.absorb(NBytes::new(appaddr))
    }
}

impl<IS, F> Absorb<&mut AppAddr> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn absorb(&mut self, appaddr: &mut AppAddr) -> SpongosResult<&mut Self> {
        self.absorb(NBytes::new(appaddr))
    }
}

impl Absorb<&Address> for sizeof::Context {
    fn absorb(&mut self, address: &Address) -> SpongosResult<&mut Self> {
        self.absorb(&address.appaddr)?.absorb(&address.msgid)
    }
}

impl<OS, F> Absorb<&Address> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn absorb(&mut self, address: &Address) -> SpongosResult<&mut Self> {
        self.absorb(&address.appaddr)?.absorb(&address.msgid)
    }
}

impl<IS, F> Absorb<&mut Address> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn absorb(&mut self, address: &mut Address) -> SpongosResult<&mut Self> {
        self.absorb(&mut address.appaddr)?.absorb(&mut address.msgid)
    }
}

impl Mask<&MsgId> for sizeof::Context {
    fn mask(&mut self, msgid: &MsgId) -> SpongosResult<&mut Self> {
        self.mask(NBytes::new(msgid))
    }
}

impl<OS, F> Mask<&MsgId> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, msgid: &MsgId) -> SpongosResult<&mut Self> {
        self.mask(NBytes::new(msgid))
    }
}

impl<IS, F> Mask<&mut MsgId> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, msgid: &mut MsgId) -> SpongosResult<&mut Self> {
        self.mask(NBytes::new(msgid))
    }
}

impl Mask<&AppAddr> for sizeof::Context {
    fn mask(&mut self, appaddr: &AppAddr) -> SpongosResult<&mut Self> {
        self.mask(NBytes::new(appaddr))
    }
}

impl<OS, F> Mask<&AppAddr> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, appaddr: &AppAddr) -> SpongosResult<&mut Self> {
        self.mask(NBytes::new(appaddr))
    }
}

impl<IS, F> Mask<&mut AppAddr> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, appaddr: &mut AppAddr) -> SpongosResult<&mut Self> {
        self.mask(NBytes::new(appaddr))
    }
}

impl Mask<&Address> for sizeof::Context {
    fn mask(&mut self, address: &Address) -> SpongosResult<&mut Self> {
        self.mask(&address.appaddr)?.mask(&address.msgid)
    }
}

impl<OS, F> Mask<&Address> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, address: &Address) -> SpongosResult<&mut Self> {
        self.mask(&address.appaddr)?.mask(&address.msgid)
    }
}

impl<IS, F> Mask<&mut Address> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, address: &mut Address) -> SpongosResult<&mut Self> {
        self.mask(&mut address.appaddr)?.mask(&mut address.msgid)
    }
}
