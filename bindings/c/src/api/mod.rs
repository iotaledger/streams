use iota_streams::{
    core::{
        prelude::*,
        psk,
    },
    app::{
        message::Cursor,
        transport::tangle::MsgId,
    },
    app_channels::api::tangle::*,
};

use core::ptr::null;
use cstr_core::{
    CStr,
    CString,
};
use cty::{
    c_char,
    size_t,
    uint8_t,
};

use iota_conversion::trytes_converter::bytes_to_trytes;

#[no_mangle]
pub extern "C" fn drop_address(addr: *const Address) {
    unsafe { Box::from_raw(addr as *mut Address); }
}


pub type PskIds = psk::PskIds;
pub type KePks = Vec<PublicKey>;

pub type NextMsgIds = Vec<(PublicKey, Cursor<Address>)>;

#[no_mangle]
pub extern "C" fn drop_next_msg_ids(m: *const NextMsgIds) {
    unsafe { Box::from_raw(m as *mut NextMsgIds); }
}

#[no_mangle]
pub extern "C" fn drop_unwrapped_message(m: *const UnwrappedMessage) {
    unsafe { Box::from_raw(m as *mut UnwrappedMessage); }
}

pub type UnwrappedMessages = Vec<UnwrappedMessage>;
#[no_mangle]
pub extern "C" fn drop_unwrapped_messages(ms: *const UnwrappedMessages) {
    unsafe { Box::from_raw(ms as *mut UnwrappedMessages); }
}

#[cfg(feature = "sync-client")]
pub type TransportWrap = iota_streams::app::transport::tangle::client::Client;

#[cfg(not(feature = "sync-client"))]
pub type TransportWrap = Rc<core::cell::RefCell<BucketTransport>>;

#[no_mangle]
pub extern "C" fn tsp_new() -> *mut TransportWrap {
    Box::into_raw(Box::new(TransportWrap::new()))
}

#[no_mangle]
pub extern "C" fn tsp_drop(tsp: *mut TransportWrap) {
    unsafe { Box::from_raw(tsp); }
}

#[cfg(feature = "sync-client")]
#[no_mangle]
pub extern "C" fn tsp_client_add_node(c_url: *const c_char) {
    use iota_streams::app::transport::tangle::client::Client;
    let url = unsafe { CStr::from_ptr(c_url).to_str().unwrap() };
    Client::new_with_node(url);
}

#[cfg(feature = "sync-client")]
#[no_mangle]
pub extern "C" fn tsp_client_set_mwm(tsp: *mut TransportWrap, mwm: uint8_t) {
    unsafe {
        tsp.as_mut().map_or((), |tsp| {
            let mut send_opt = (&*tsp).get_send_options();
            send_opt.min_weight_magnitude = mwm;
            tsp.set_send_options(send_opt);
        })
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
        Self {
            msg_link,
            seq_link,
        }
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
pub struct PacketPayloads {
    public_payload_ptr: *const uint8_t,
    public_payload_size: size_t,
    public_payload_cap: size_t,
    masked_payload_ptr: *const uint8_t,
    masked_payload_size: size_t,
    masked_payload_cap: size_t,
}

impl Default for PacketPayloads {
    fn default() -> Self {
        Self {
            public_payload_ptr: null(),
            public_payload_size: 0,
            public_payload_cap: 0,
            masked_payload_ptr: null(),
            masked_payload_size: 0,
            masked_payload_cap: 0,
        }
    }
}

impl From<(Bytes, Bytes)> for PacketPayloads {
    fn from(payloads: (Bytes, Bytes)) -> Self {
        let p = core::mem::ManuallyDrop::new(payloads.0.0);
        let m = core::mem::ManuallyDrop::new(payloads.1.0);
        Self {
            public_payload_ptr: p.as_ptr(),
            public_payload_size: p.len(),
            public_payload_cap: p.capacity(),
            masked_payload_ptr: m.as_ptr(),
            masked_payload_size: m.len(),
            masked_payload_cap: m.capacity(),
        }
    }
}

impl<'a> From<(&'a Bytes, &'a Bytes)> for PacketPayloads {
    fn from(payloads: (&Bytes, &Bytes)) -> Self {
        let p = &payloads.0.0;
        let m = &payloads.1.0;
        Self {
            public_payload_ptr: p.as_ptr(),
            public_payload_size: p.len(),
            public_payload_cap: p.capacity(),
            masked_payload_ptr: m.as_ptr(),
            masked_payload_size: m.len(),
            masked_payload_cap: m.capacity(),
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
        unsafe {
            Vec::from_raw_parts(
                self.public_payload_ptr as *mut u8,
                self.public_payload_size,
                self.public_payload_cap,
            );
            Vec::from_raw_parts(
                self.masked_payload_ptr as *mut u8,
                self.masked_payload_size,
                self.masked_payload_cap,
            );
        }
    }
}

#[no_mangle]
pub extern "C" fn drop_payloads(payloads: PacketPayloads) {
    payloads.drop()
}

#[no_mangle]
pub extern "C" fn drop_str(s: *const c_char) {
    unsafe { CString::from_raw(s as *mut c_char); }
}

#[no_mangle]
pub extern "C" fn get_channel_address_str(appinst: *const ChannelAddress) -> *const c_char {
    unsafe {
        CString::new(bytes_to_trytes((*appinst).as_ref())).unwrap().into_raw()
    }
}

#[no_mangle]
pub extern "C" fn get_msgid_str(msgid: *mut MsgId) -> *const c_char {
    unsafe {
        CString::new(bytes_to_trytes((*msgid).as_ref())).unwrap().into_raw()
    }
}

#[no_mangle]
pub extern "C" fn get_address_inst_str(address: *mut Address) -> *mut c_char {
    unsafe {
        CString::new(bytes_to_trytes((*address).appinst.as_ref())).unwrap().into_raw()
    }
}

#[no_mangle]
pub extern "C" fn get_address_id_str(address: *mut Address) -> *mut c_char {
    unsafe {
        CString::new(bytes_to_trytes((*address).msgid.as_ref())).unwrap().into_raw()
    }
}

#[no_mangle]
pub extern "C" fn get_payload(msg: *const UnwrappedMessage) -> PacketPayloads {
    unsafe {
        msg.as_ref().map_or(PacketPayloads::default(), handle_message_contents)
    }
}

#[no_mangle]
pub extern "C" fn get_indexed_payload(msgs: *const UnwrappedMessages, index: size_t) -> PacketPayloads {
    unsafe {
        msgs.as_ref().map_or(PacketPayloads::default(), |msgs| {
            handle_message_contents(&msgs[index])
        })
    }
}

fn handle_message_contents(m: &UnwrappedMessage) -> PacketPayloads {
    match &m.body {
        MessageContent::TaggedPacket { public_payload: p, masked_payload: m, } => (p, m).into(),

        MessageContent::SignedPacket { pk: _, public_payload: p, masked_payload: m } => (p, m).into(),

        _ => PacketPayloads::default(),
    }
}

mod auth;
pub use auth::*;

mod sub;
pub use sub::*;
