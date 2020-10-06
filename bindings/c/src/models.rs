//! Default parameters for Author and Subscriber types.

use iota_streams::app::{
    message,
    transport::{
        tangle::{
            AppInst as ApplicationInstance,
            TangleAddress,
            MsgId as MessageId,
        },
    },
};
use iota_streams::core::psk;

use iota_streams::app_channels::api::tangle::{
    Author as Auth,
    Subscriber as Sub,
    Preparsed as PreparsedMessage,
    MessageReturn,
    Transport,
};

use iota_conversion::trytes_converter::{
    bytes_to_trytes
};
use iota_streams::core_keccak::sponge::prp::keccak::KeccakF1600;
use iota_streams::core_edsig::signature::ed25519;

use std::os::raw::{c_char, c_int};
use std::ffi::CString;

pub struct AppInst(pub(crate) ApplicationInstance);

#[no_mangle]
pub extern "C" fn get_appinst_str(appinst: *mut AppInst) -> *mut c_char {
    unsafe {
        let unboxed = Box::from_raw(appinst).0;
        CString::new(bytes_to_trytes(unboxed.as_ref())).unwrap().into_raw()
    }
}

pub struct MsgId(pub(crate) MessageId);

#[no_mangle]
pub extern "C" fn get_msgid_str(msgid: *mut MsgId) -> *mut c_char{
    unsafe {
        let unboxed = Box::from_raw(msgid).0;
        CString::new(bytes_to_trytes(unboxed.as_ref())).unwrap().into_raw()
    }
}

#[derive(Clone)]
pub struct Address(pub(crate) TangleAddress);

#[no_mangle]
pub extern "C" fn get_address_inst_str(address: *mut Address) -> *mut c_char {
    unsafe {
        let unboxed = Box::from_raw(address);
        //TODO: do not discard appinst in returned string
        self::get_appinst_str(Box::into_raw(Box::new(AppInst(unboxed.0.appinst.clone()))));

        CString::new(bytes_to_trytes(unboxed.0.msgid.as_ref())).unwrap().into_raw()
    }
}

#[no_mangle]
pub extern "C" fn get_address_id_str(address: *mut Address) -> *mut c_char {
    unsafe {
        let unboxed = Box::from_raw(address);
        self::get_msgid_str(Box::into_raw(Box::new(MsgId(unboxed.0.msgid.clone()))));

        CString::new(bytes_to_trytes(unboxed.0.msgid.as_ref())).unwrap().into_raw()
    }
}

pub struct TangleTransport<T: Transport>(pub(crate) T);


pub struct Author<T: Transport> {
    pub(crate) auth: Auth<T>,
}

pub struct Subscriber<T: Transport> {
    pub(crate) sub: Sub<T>,
}

pub struct Message(pub(crate) message::BinaryMessage<KeccakF1600, TangleAddress>);

impl Default for Message {
    fn default() -> Message {
        Message(message::BinaryMessage::new(TangleAddress::default(), vec![]))
    }
}

pub struct MsgReturn(pub(crate) MessageReturn);

pub struct MessageReturns(pub(crate) Vec<MsgReturn>);

pub struct PskIds(pub(crate) psk::PskIds);

pub struct PubKey(pub(crate) ed25519::PublicKey);

pub struct KePks(pub(crate) Vec<ed25519::PublicKey>);

pub struct SeqState {
    pub(crate) address: Address,
    pub(crate) state: usize,
} // (Address, usize[size_t])

pub struct NextMsgId{
    pub(crate) pubkey: PubKey,
    pub(crate) seq_state: SeqState,
} // vec(Pubkey, (address, usize))

pub struct NextMsgIds{
    pub(crate) ids: Vec<NextMsgId>
}

pub struct Preparsed<'a>(pub(crate) PreparsedMessage<'a>);

pub struct MessageLinks{
    pub(crate) msg_link: Address,
    pub(crate) seq_link: Option<Address>,
}

#[repr(C)]
pub struct PayloadResponse {
    pub(crate) public_payload: *const c_char,
    pub(crate) private_payload: *const c_char,
}

#[no_mangle]
pub extern "C" fn get_payload(msg: *mut MsgReturn) -> *mut PayloadResponse  {
    unsafe {
        let unboxed = Box::from_raw(msg);

        let ptr = Box::into_raw(Box::new(PayloadResponse {
            public_payload: CString::from_vec_unchecked(unboxed.0.public_payload.0.clone()).into_raw(),
            private_payload: CString::from_vec_unchecked(unboxed.0.masked_payload.0.clone()).into_raw(),
        }));
        std::mem::forget(unboxed);
        ptr
    }
}

#[no_mangle]
pub extern "C" fn get_indexed_payload(msgs: *mut MessageReturns, index: u32) -> *mut PayloadResponse  {
    unsafe {
        let unboxed = Box::from_raw(msgs);
        let payload = &unboxed.0[index as usize].0;
        let ptr = Box::into_raw(Box::new(PayloadResponse {
            public_payload: CString::from_vec_unchecked(payload.public_payload.0.clone()).into_raw(),
            private_payload: CString::from_vec_unchecked(payload.masked_payload.0.clone()).into_raw(),
        }));
        std::mem::forget(unboxed);
        ptr
    }
}


#[no_mangle]
pub extern "C" fn get_msg_link(msg_links: *mut MessageLinks) -> *mut Address {
    unsafe {
        let unboxed = Box::from_raw(msg_links);
        let ptr = Box::into_raw(Box::new(Address(unboxed.msg_link.0.clone())));
        std::mem::forget(unboxed);
        ptr
    }
}

#[no_mangle]
pub extern "C" fn get_seq_link(msg_links: *mut MessageLinks) -> *mut Address {
    unsafe {
        let unboxed = Box::from_raw(msg_links);
        let ptr = Box::into_raw(Box::new(unboxed.seq_link.clone().unwrap()));
        std::mem::forget(unboxed);
        ptr
    }
}
