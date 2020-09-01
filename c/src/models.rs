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
    Transport as Trans,
};


use iota_streams::core_keccak::sponge::prp::keccak::KeccakF1600;
use iota_streams::core_edsig::key_exchange::x25519;

use std::os::raw::c_char;
use std::ffi::CString;

pub struct AppInst(pub(crate) ApplicationInstance);

#[no_mangle]
pub extern "C" fn get_appinst_str(appinst: *mut AppInst) -> *mut c_char {
    unsafe {
        let unboxed = Box::from_raw(appinst).0;
        assert!(!unboxed.tbits().is_empty(), "App instance can't be empty");
        CString::new(hex::encode(unboxed.tbits().clone())).unwrap().into_raw()
    }
}

pub struct MsgId(pub(crate) MessageId);

#[no_mangle]
pub extern "C" fn get_msgid_str(msgid: *mut MsgId) -> *mut c_char{
    unsafe {
        let unboxed = Box::from_raw(msgid).0;
        assert!(!unboxed.tbits().is_empty(), "Msg Id can't be empty");
        CString::new(hex::encode(unboxed.tbits().clone())).unwrap().into_raw()    }
}

pub struct Address(pub(crate) TangleAddress);

#[no_mangle]
pub extern "C" fn get_address_inst_str(address: *mut Address) -> *mut c_char {
    unsafe {
        let unboxed = Box::from_raw(address);
        assert!(!unboxed.0.appinst.tbits().is_empty(), "App instance can't be empty");
        self::get_appinst_str(Box::into_raw(Box::new(AppInst(unboxed.0.appinst.clone()))));

        CString::new(hex::encode(unboxed.0.appinst.tbits().clone())).unwrap().into_raw()
    }
}

#[no_mangle]
pub extern "C" fn get_address_id_str(address: *mut Address) -> *mut c_char {
    unsafe {
        let unboxed = Box::from_raw(address);
        assert!(!unboxed.0.msgid.tbits().is_empty(), "App instance can't be empty");
        self::get_msgid_str(Box::into_raw(Box::new(MsgId(unboxed.0.msgid.clone()))));

        CString::new(hex::encode(unboxed.0.msgid.tbits().clone())).unwrap().into_raw()
    }
}

pub struct Transport<'a>(pub(crate) &'a iota::Client);

//pub struct Author<'a, T: Trans>{
pub struct Author {
    pub(crate) auth: Auth,
    //pub(crate) transport: Transport<'a>,
}

pub struct Subscriber{
    pub(crate) sub: Sub,
    //pub(crate) transport: Transport,
}

pub struct Message(pub(crate) message::BinaryMessage<KeccakF1600, TangleAddress>);

pub struct PskIds(pub(crate) psk::PskIds);

pub struct PubKey(pub(crate) x25519::PublicKey);

pub struct PubKeyWrap(pub(crate) x25519::PublicKeyWrap);

pub struct KePks(pub(crate) Vec<x25519::PublicKeyWrap>);

pub struct SeqState {
    pub(crate) address: Address,
    pub(crate) state: usize,
} // (Address, usize[size_t])

pub struct NextMsgId{
    pub(crate) pubkey: PubKey,
    pub(crate) seq_state: SeqState,
} // vec(Pubkey, (address, usize))

pub struct Preparsed<'a>(pub(crate) PreparsedMessage<'a>);
