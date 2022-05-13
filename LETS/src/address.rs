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
    str::FromStr,
};

// 3rd-party
use anyhow::{
    anyhow,
    Result,
};

// IOTA

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
    KeccakF1600,
    Spongos,
    PRP,
};

// Local
use crate::id::Identifier;

/// Abstract representation of a Message Address
///
/// An `Address` is comprised of 2 distinct parts: the application address
/// ([`Address::appaddr`]) and the message identifier ([`Address::msgid`]). The
/// application address is unique per application and is common in the `Address`
/// of all messages published in it. The message identifier is produced
/// pseudo-randomly out of the publisher's identifier and the message's sequence
/// number
///
/// ## exchangeable encoding
/// In order to exchange an `Address` between application participants, it can be encoded and decoded
/// using [`Address::to_string()`][Display] (or [`format!()`]) and [`Address::from_str`] (or
/// [`str::parse()`]). This method encodes the `Address` as a colon-separated string containing the `appaddr` and
/// `msgid` in hexadecimal:
/// ```
/// # use LETS::address::Address;
/// #
/// # fn main() -> anyhow::Result<()> {
/// let address = Address::new([170; 40], [255; 12]);
/// let address_str = address.to_string();
/// assert_eq!(
///     address_str,
///     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:ffffffffffffffffffffffff"
///         .to_string(),
/// );
/// assert_eq!(address_str.parse::<Address>()?, address);
/// #   Ok(())
/// # }
/// ```
///
/// ## Debugging
///
/// For debugging purposes, `Address` implements `Debug`, which can be triggered with the formatting `{:?}`
/// or the pretty-printed `{:#?}`. These will output `appaddr` and `msgid` as decimal arrays; you can also use
/// `{:x?}` or `{:#x?}` to render them as hexadecimal arrays.
///
/// [Display]: #impl-Display
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct Address {
    appaddr: AppAddr,
    msgid: MsgId,
}

impl Address {
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
    type Err = anyhow::Error;
    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let (appaddr_str, msgid_str) = string.split_once(':').ok_or_else(|| {
            anyhow!("Malformed address string: missing colon (':') separator between appaddr and msgid")
        })?;
        let appaddr = AppAddr::from_str(appaddr_str).map_err(|e| {
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

/// 40 byte Application Instance identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AppAddr([u8; Self::SIZE]);

impl AppAddr {
    const SIZE: usize = 40;

    pub fn new(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }

    pub fn gen(identifier: Identifier, app_idx: usize) -> AppAddr {
        let mut addr = [0u8; 40];
        let id_bytes = identifier.as_bytes();
        assert_eq!(id_bytes.len(), 32, "identifier must be 32 bytes long");
        addr[..32].copy_from_slice(id_bytes);
        addr[32..].copy_from_slice(&app_idx.to_be_bytes());
        Self::new(addr)
    }

    /// Get the hexadecimal representation of the appaddr
    fn to_hex_string(self) -> String {
        hex::encode(self.0)
    }

    /// Get a view into the internal byte array that constitutes an [`AppAddr`]
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
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MsgId([u8; Self::SIZE]);

impl MsgId {
    const SIZE: usize = 12;

    pub fn new(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }

    pub fn gen(appaddr: AppAddr, identifier: Identifier, seq_num: usize) -> MsgId {
        let mut s = Spongos::<KeccakF1600>::init();
        s.absorb(appaddr);
        s.absorb(identifier);
        s.absorb(seq_num.to_be_bytes());
        s.commit();
        s.squeeze()
    }

    /// Get the hexadecimal representation of the MsgId
    fn to_hex_string(self) -> String {
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

impl From<[u8; 12]> for MsgId {
    fn from(array: [u8; 12]) -> Self {
        Self(array)
    }
}

impl Absorb<&MsgId> for sizeof::Context {
    fn absorb(&mut self, msgid: &MsgId) -> Result<&mut Self> {
        self.absorb(NBytes::new(msgid))
    }
}

impl<OS, F> Absorb<&MsgId> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn absorb(&mut self, msgid: &MsgId) -> Result<&mut Self> {
        self.absorb(NBytes::new(msgid))
    }
}

impl<IS, F> Absorb<&mut MsgId> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn absorb(&mut self, msgid: &mut MsgId) -> Result<&mut Self> {
        self.absorb(NBytes::new(msgid))
    }
}

impl Absorb<&AppAddr> for sizeof::Context {
    fn absorb(&mut self, appaddr: &AppAddr) -> Result<&mut Self> {
        self.absorb(NBytes::new(appaddr))
    }
}

impl<OS, F> Absorb<&AppAddr> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn absorb(&mut self, appaddr: &AppAddr) -> Result<&mut Self> {
        self.absorb(NBytes::new(appaddr))
    }
}

impl<IS, F> Absorb<&mut AppAddr> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn absorb(&mut self, appaddr: &mut AppAddr) -> Result<&mut Self> {
        self.absorb(NBytes::new(appaddr))
    }
}

impl Absorb<&Address> for sizeof::Context {
    fn absorb(&mut self, address: &Address) -> Result<&mut Self> {
        self.absorb(&address.appaddr)?.absorb(&address.msgid)
    }
}

impl<OS, F> Absorb<&Address> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn absorb(&mut self, address: &Address) -> Result<&mut Self> {
        self.absorb(&address.appaddr)?.absorb(&address.msgid)
    }
}

impl<IS, F> Absorb<&mut Address> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn absorb(&mut self, address: &mut Address) -> Result<&mut Self> {
        self.absorb(&mut address.appaddr)?.absorb(&mut address.msgid)
    }
}

impl Mask<&MsgId> for sizeof::Context {
    fn mask(&mut self, msgid: &MsgId) -> Result<&mut Self> {
        self.mask(NBytes::new(msgid))
    }
}

impl<OS, F> Mask<&MsgId> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, msgid: &MsgId) -> Result<&mut Self> {
        self.mask(NBytes::new(msgid))
    }
}

impl<IS, F> Mask<&mut MsgId> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, msgid: &mut MsgId) -> Result<&mut Self> {
        self.mask(NBytes::new(msgid))
    }
}

impl Mask<&AppAddr> for sizeof::Context {
    fn mask(&mut self, appaddr: &AppAddr) -> Result<&mut Self> {
        self.mask(NBytes::new(appaddr))
    }
}

impl<OS, F> Mask<&AppAddr> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, appaddr: &AppAddr) -> Result<&mut Self> {
        self.mask(NBytes::new(appaddr))
    }
}

impl<IS, F> Mask<&mut AppAddr> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, appaddr: &mut AppAddr) -> Result<&mut Self> {
        self.mask(NBytes::new(appaddr))
    }
}

impl Mask<&Address> for sizeof::Context {
    fn mask(&mut self, address: &Address) -> Result<&mut Self> {
        self.mask(&address.appaddr)?.mask(&address.msgid)
    }
}

impl<OS, F> Mask<&Address> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, address: &Address) -> Result<&mut Self> {
        self.mask(&address.appaddr)?.mask(&address.msgid)
    }
}

impl<IS, F> Mask<&mut Address> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, address: &mut Address) -> Result<&mut Self> {
        self.mask(&mut address.appaddr)?.mask(&mut address.msgid)
    }
}
