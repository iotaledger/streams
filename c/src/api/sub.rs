use crate::{AppInst, Address, Subscriber, Message, PskIds, KePks, MessageLinks, PayloadResponse, SeqState, Preparsed, utils, client};

use iota_streams::app_channels::api::tangle::{
    Subscriber as Sub, 
    Message as TangleMessage,
    Preparsed as PreparsedMessage,
};
use iota_streams::app::transport::{
    tangle::{
        TangleAddress,
        AppInst as ApplicationInstance,
        MsgId as MessageIdentifier,
    }
};
use iota_streams::ddml::types::Bytes;

use std::mem;
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::{c_char, c_ulonglong};
use iota::client::Client;
use crate::constants::*;

/// Create a new subscriber
#[no_mangle]
pub extern "C" fn sub_new(seed: *const c_char , encoding: *const c_char, payload_length: *const c_ulonglong) -> *mut Subscriber {
    let c_seed = unsafe {
        CStr::from_ptr(seed)
    };

    let c_encoding = unsafe {
        CStr::from_ptr(encoding)
    };

    Client::get();
    Client::add_node(URL).unwrap();

    let sub = Sub::new(c_seed.to_str().unwrap(), c_encoding.to_str().unwrap(), payload_length as usize);
    Box::into_raw(Box::new(Subscriber{ sub }))
}

/// Handle Channel app instance announcement.
#[no_mangle]
pub extern "C" fn sub_unwrap_announce(subscriber: *mut Subscriber, message: *mut TangleMessage){
    unsafe {
        let mut sub = Box::from_raw(subscriber);
        let msg = Box::from_raw(message);

        let parsed = msg.parse_header();
        
        sub.sub.unwrap_announcement(parsed.unwrap()).unwrap();
        mem::forget(sub);
        mem::forget(msg);
    }
}

#[no_mangle]
pub extern "C" fn sub_get_branching_flag(subscriber: *mut Subscriber) -> u8 {
    unsafe {
        let sub = Box::from_raw(subscriber);
        let branching = if sub.sub.is_multi_branching() { 1 } else { 0 };
        mem::forget(sub);

        branching
    }
}

/// Subscribe to a Channel app instance.
#[no_mangle]
pub extern "C" fn sub_subscribe(subscriber: *mut Subscriber, announcement_link: *mut Address) -> *mut Address {
    let mut sub = unsafe { Box::from_raw(subscriber) };
    let unboxed_address = unsafe { Box::from_raw(announcement_link) };
    let tangle_address = Address(
        TangleAddress::new(unboxed_address.0.appinst.clone(), unboxed_address.0.msgid.clone())
    );
    std::mem::forget(unboxed_address);

    let msg = sub.sub.subscribe(&tangle_address.0).unwrap();
    mem::forget(sub);

    let mut client = Client::get();
    client::send_message(&mut client, &Message(msg.clone()));
    Box::into_raw(Box::new(Address(msg.link)))
}

/// Process a keyload message 
#[no_mangle]
pub extern "C" fn sub_unwrap_keyload(subscriber: *mut Subscriber, message: *mut TangleMessage) {
    unsafe {
        let mut sub = Box::from_raw(subscriber);

        let msg = Box::from_raw(message);
        let parsed = msg.parse_header();
        
        sub.sub.unwrap_keyload(parsed.unwrap()).unwrap();
        mem::forget(sub);
        mem::forget(msg);
    }
}

#[no_mangle]
pub extern "C" fn sub_unwrap_sequence(subscriber: *mut Subscriber, message: *mut TangleMessage) -> *mut Address {
    unsafe {
        let mut sub = Box::from_raw(subscriber);

        let msg = Box::from_raw(message);
        let parsed = msg.parse_header();
        
        let addr = sub.sub.unwrap_sequence(parsed.unwrap()).unwrap();
        mem::forget(sub);
        mem::forget(msg);

        Box::into_raw(Box::new(Address(addr)))
    }
}

/// Process a Signed packet message 
#[no_mangle]
pub extern "C" fn sub_unwrap_signed_packet(subscriber: *mut Subscriber, message: *mut TangleMessage) -> *mut PayloadResponse {
    unsafe {
        let mut sub = Box::from_raw(subscriber);

        let msg = Box::from_raw(message);
        let parsed = msg.parse_header();
        
        let (_signer_pk, unwrapped_public, unwrapped_masked) = sub.sub.unwrap_signed_packet(parsed.unwrap()).unwrap();
        mem::forget(sub);
        mem::forget(msg);
        
        Box::into_raw(Box::new(PayloadResponse {
            public_payload: CString::from_vec_unchecked(unwrapped_public.0).into_raw(),
            private_payload: CString::from_vec_unchecked(unwrapped_masked.0).into_raw(),
        }))
    }
}

/// Process a tagged packet message 
#[no_mangle]
pub extern "C" fn sub_unwrap_tagged_packet(subscriber: *mut Subscriber, message: *mut TangleMessage) -> *mut PayloadResponse {
    unsafe {
        let mut sub = Box::from_raw(subscriber);

        let msg = Box::from_raw(message);
        let parsed = msg.parse_header();
        
        let (unwrapped_public, unwrapped_masked) = sub.sub.unwrap_tagged_packet(parsed.unwrap()).unwrap();
        mem::forget(sub);
        mem::forget(msg);

        Box::into_raw(Box::new(PayloadResponse {
            public_payload: CString::from_vec_unchecked(unwrapped_public.0).into_raw(),
            private_payload: CString::from_vec_unchecked(unwrapped_masked.0).into_raw(),
        }))
    }
}
