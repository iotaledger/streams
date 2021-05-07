use iota_streams::{
    app::{
        cstr_core::{
            CStr,
            CString,
        },
        cty::{
            c_char,
            size_t,
            uint8_t,
        },
        message::Cursor,
        transport::tangle::{
            MsgId,
            client::get_hash,
        },
    },
    app_channels::api::tangle::*,
    core::{
        prelude::*,
        psk,
    },
};

use core::ptr::{
    null,
    null_mut,
};

#[no_mangle]
pub extern "C" fn address_from_string(c_addr: *const c_char) -> *const Address {
    unsafe {
        Address::from_c_str(c_addr)
    }
}

#[no_mangle]
pub extern "C" fn public_key_to_string(pubkey: *const PublicKey) -> *const c_char {
    unsafe {
        pubkey.as_ref().map_or(null(), |pk| {
            CString::new(hex::encode(pk.as_bytes())).map_or(null(), |pk| pk.into_raw())
        })
    }
}

#[no_mangle]
pub extern "C" fn drop_address(addr: *const Address) {
    unsafe {
        Box::from_raw(addr as *mut Address);
    }
}

pub type PskIds = psk::PskIds;
pub type KePks = Vec<PublicKey>;

pub type NextMsgIds = Vec<(PublicKey, Cursor<Address>)>;

#[no_mangle]
pub extern "C" fn drop_next_msg_ids(m: *const NextMsgIds) {
    unsafe {
        Box::from_raw(m as *mut NextMsgIds);
    }
}

pub type UserState = Vec<(String, Cursor<Address>)>;
#[no_mangle]
pub extern "C" fn drop_user_state(s: *const UserState) {
    unsafe {
        Box::from_raw(s as *mut UserState);
    }
}

#[no_mangle]
pub extern "C" fn get_link_from_state(s: *const UserState, pub_key: *const PublicKey) -> *const Address {
    unsafe {
        s.as_ref().map_or(null(), |state| {
            pub_key.as_ref().map_or(null(), |pub_key| {
                let pk_str = hex::encode(pub_key.as_bytes());
                for (pk, cursor) in state {
                    if pk == &pk_str {
                        return Box::into_raw(Box::new(cursor.link.clone()))
                    }
                }
                return null()
            })
        })
    }
}

pub type UnwrappedMessages = Vec<UnwrappedMessage>;
#[no_mangle]
pub extern "C" fn drop_unwrapped_messages(ms: *const UnwrappedMessages) {
    unsafe {
        Box::from_raw(ms as *mut UnwrappedMessages);
    }
}



#[cfg(feature = "sync-client")]
pub type TransportWrap = iota_streams::app::transport::tangle::client::Client;

#[cfg(not(feature = "sync-client"))]
pub type TransportWrap = Rc<core::cell::RefCell<BucketTransport>>;

#[no_mangle]
pub extern "C" fn tsp_new() -> *mut TransportWrap {
    Box::into_raw(Box::new(TransportWrap::default()))
}

#[no_mangle]
pub extern "C" fn tsp_drop(tsp: *mut TransportWrap) {
    unsafe {
        Box::from_raw(tsp);
    }
}

#[cfg(feature = "sync-client")]
#[no_mangle]
pub extern "C" fn tsp_client_new_from_url(c_url: *const c_char) -> *mut TransportWrap {
    unsafe {
        let url = CStr::from_ptr(c_url).to_str().unwrap();

        Box::into_raw(Box::new(TransportWrap::new_from_url(url)))
    }
}

#[repr(C)]
pub struct MessageLinks {
    pub msg_link: *const Address,
    pub seq_link: *const Address,
}

impl From<(Address, Option<Address>)> for MessageLinks {
    fn from(links: (Address, Option<Address>)) -> Self {
        let msg_link = Box::into_raw(Box::new(links.0));
        let seq_link = links.1.map_or(null(), |s| Box::into_raw(Box::new(s)));
        Self { msg_link, seq_link }
    }
}

impl MessageLinks {
    pub fn into_seq_link<'a>(self, branching: bool) -> Option<&'a Address> {
        unsafe {
            if !branching {
                self.msg_link.as_ref()
            } else {
                self.seq_link.as_ref()
            }
        }
    }

    pub fn drop(self) {
        unsafe {
            Box::from_raw(self.msg_link as *mut Address);
            if self.seq_link != null() {
                Box::from_raw(self.seq_link as *mut Address);
            }
        }
    }
}

impl Default for MessageLinks {
    fn default() -> Self {
        Self {
            msg_link: null(),
            seq_link: null(),
        }
    }
}

#[no_mangle]
pub extern "C" fn drop_links(links: MessageLinks) {
    links.drop()
}

#[repr(C)]
pub struct Buffer {
    ptr: *const uint8_t,
    size: size_t,
    cap: size_t,
}

impl Default for Buffer {
    fn default() -> Self {
        Self {
            ptr: null(),
            size: 0,
            cap: 0,
        }
    }
}

impl From<Bytes> for Buffer {
    fn from(b: Bytes) -> Self {
        let p = core::mem::ManuallyDrop::new(b.0);
        Self {
            ptr: p.as_ptr(),
            size: p.len(),
            cap: p.capacity(),
        }
    }
}

impl<'a> From<&'a Bytes> for Buffer {
    fn from(b: &Bytes) -> Self {
        let p = &b.0;
        Self {
            ptr: p.as_ptr(),
            size: p.len(),
            cap: p.capacity(),
        }
    }
}

impl Buffer {
    pub fn drop(self) {
        unsafe {
            Vec::from_raw_parts(self.ptr as *mut u8, self.size, self.cap);
        }
    }
}

#[no_mangle]
pub extern "C" fn drop_buffer(b: Buffer) {
    b.drop()
}

#[repr(C)]
pub struct PacketPayloads {
    public_payload: Buffer,
    masked_payload: Buffer,
}

impl Default for PacketPayloads {
    fn default() -> Self {
        Self {
            public_payload: Buffer::default(),
            masked_payload: Buffer::default(),
        }
    }
}

impl From<(Bytes, Bytes)> for PacketPayloads {
    fn from(payloads: (Bytes, Bytes)) -> Self {
        Self {
            public_payload: Buffer::from(payloads.0),
            masked_payload: Buffer::from(payloads.1),
        }
    }
}

impl<'a> From<(&'a Bytes, &'a Bytes)> for PacketPayloads {
    fn from(payloads: (&Bytes, &Bytes)) -> Self {
        Self {
            public_payload: Buffer::from(payloads.0),
            masked_payload: Buffer::from(payloads.1),
        }
    }
}

impl From<(PublicKey, Bytes, Bytes)> for PacketPayloads {
    fn from(signed_payloads: (PublicKey, Bytes, Bytes)) -> Self {
        let payloads = (signed_payloads.1, signed_payloads.2);
        PacketPayloads::from(payloads)
    }
}

impl PacketPayloads {
    pub fn drop(self) {
        self.public_payload.drop();
        self.masked_payload.drop();
    }
}

#[no_mangle]
pub extern "C" fn drop_payloads(payloads: PacketPayloads) {
    payloads.drop()
}

#[no_mangle]
pub extern "C" fn drop_str(s: *const c_char) {
    unsafe {
        CString::from_raw(s as *mut c_char);
    }
}

#[no_mangle]
pub extern "C" fn get_channel_address_str(appinst: *const ChannelAddress) -> *const c_char {
    unsafe {
        appinst.as_ref().map_or(null(), |inst| {
            CString::new(hex::encode(inst)).map_or(null(), |inst_str| inst_str.into_raw())
        })
    }
}

#[no_mangle]
pub extern "C" fn get_msgid_str(msgid: *mut MsgId) -> *const c_char {
    unsafe {
        msgid.as_ref().map_or(null(), |id| {
            CString::new(hex::encode(id)).map_or(null(), |id_str| id_str.into_raw())
        })
    }
}

#[no_mangle]
pub extern "C" fn get_address_inst_str(address: *mut Address) -> *mut c_char {
    unsafe {
        address.as_ref().map_or(null_mut(), |addr| {
            CString::new(hex::encode(addr.appinst.as_ref())).map_or(null_mut(), |inst| inst.into_raw())
        })
    }
}

#[no_mangle]
pub extern "C" fn get_address_id_str(address: *mut Address) -> *mut c_char {
    unsafe {
        address.as_ref().map_or(null_mut(), |addr| {
            CString::new(hex::encode(addr.msgid.as_ref())).map_or(null_mut(), |id| id.into_raw())
        })
    }
}

#[no_mangle]
pub extern "C" fn get_address_index_str(address: *mut Address) -> *mut c_char {
    unsafe {
        address.as_ref().map_or(null_mut(), |addr| {
            get_hash(addr.appinst.as_ref(), addr.msgid.as_ref())
                .map_or(null_mut(), |index| {
                    CString::new(index)
                        .map_or(null_mut(), |index| index.into_raw())
                })
        })
    }

}

#[no_mangle]
pub extern "C" fn get_payload(msg: *const UnwrappedMessage) -> PacketPayloads {
    unsafe { msg.as_ref().map_or(PacketPayloads::default(), handle_message_contents) }
}

#[no_mangle]
pub extern "C" fn get_indexed_payload(msgs: *const UnwrappedMessages, index: size_t) -> PacketPayloads {
    unsafe {
        msgs.as_ref()
            .map_or(PacketPayloads::default(), |msgs| handle_message_contents(&msgs[index]))
    }
}

fn handle_message_contents(m: &UnwrappedMessage) -> PacketPayloads {
    match &m.body {
        MessageContent::TaggedPacket {
            public_payload: p,
            masked_payload: m,
        } => (p, m).into(),

        MessageContent::SignedPacket {
            pk: _,
            public_payload: p,
            masked_payload: m,
        } => (p, m).into(),

        _ => PacketPayloads::default(),
    }
}

mod auth;
pub use auth::*;

mod sub;
pub use sub::*;
