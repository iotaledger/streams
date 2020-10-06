use crate::{Address, Subscriber, PayloadResponse, AppInst, PubKey, NextMsgId, NextMsgIds, SeqState, MessageReturns, MsgReturn};

use iota_streams::app_channels::api::tangle::{
    Subscriber as Sub,
    Address as TangleAddress,
    Message as TangleMessage,
};
use iota_streams::app::transport::Transport;

use std::mem;
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::{c_char, c_ulonglong};
use iota::client::Client;
use crate::constants::*;

/// Create a new subscriber
#[no_mangle]
pub extern "C" fn sub_new<'a>(seed: *const c_char , encoding: *const c_char, payload_length: *const c_ulonglong) -> *mut Subscriber<&'a Client>
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
let c_seed = unsafe {
        CStr::from_ptr(seed)
    };

    let c_encoding = unsafe {
        CStr::from_ptr(encoding)
    };

    let client = Client::get();
    Client::add_node(URL).unwrap();
    let sub = Sub::new(c_seed.to_str().unwrap(), c_encoding.to_str().unwrap(), payload_length as usize, client);
    Box::into_raw(Box::new(Subscriber{ sub }))
}

/// Handle Channel app instance announcement.
#[no_mangle]
pub extern "C" fn sub_receive_announce<'a>(subscriber: *mut Subscriber<&'a Client>, link: *mut Address)
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
unsafe {
        let mut sub = Box::from_raw(subscriber);
        let link = Box::from_raw(link);

        println!("Link to announcement being unwrapped: {}", link.0);
        sub.sub.receive_announcement(&link.0).unwrap();
        mem::forget(sub);
        mem::forget(link);
    }
}

/// Channel app instance.
#[no_mangle]
pub extern "C" fn sub_channel_address<'a>(subscriber: *mut Subscriber<&'a Client>) -> *mut AppInst
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
    unsafe {
        let sub = Box::from_raw(subscriber);
        if let Some(channel_address) = sub.sub.channel_address() {
            let appinst = AppInst(channel_address.clone());
            mem::forget(sub);
            Box::into_raw(Box::new(appinst))
        } else {
            std::ptr::null_mut()
        }
    }
}


#[no_mangle]
pub extern "C" fn sub_get_branching_flag<'a>(subscriber: *mut Subscriber<&'a Client>) -> u8
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
unsafe {
        let sub = Box::from_raw(subscriber);
        let branching = if sub.sub.is_multi_branching() { 1 } else { 0 };
        mem::forget(sub);

        branching
    }
}

#[no_mangle]
pub extern "C" fn sub_get_pk<'a>(subscriber: *mut Subscriber<&'a Client>) -> *mut PubKey
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
    unsafe {
        let sub = Box::from_raw(subscriber);
        let pk = sub.sub.get_pk().clone();
        mem::forget(sub);

        Box::into_raw(Box::new(PubKey(pk)))
    }
}

#[no_mangle]
pub extern "C" fn sub_is_registered<'a>(subscriber: *mut Subscriber<&'a Client>) -> u8
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
    unsafe {
        let sub = Box::from_raw(subscriber);
        let registered = if sub.sub.is_registered() { 1 } else { 0 };
        mem::forget(sub);

        registered
    }
}

#[no_mangle]
pub extern "C" fn sub_unregister<'a>(subscriber: *mut Subscriber<&'a Client>)
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
    unsafe {
        let mut sub = Box::from_raw(subscriber);
        sub.sub.unregister();
        mem::forget(sub);
    }
}



/// Subscribe to a Channel app instance.
#[no_mangle]
pub extern "C" fn sub_send_subscribe<'a>(subscriber: *mut Subscriber<&'a Client>, announcement_link: *mut Address) -> *mut Address
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
    let mut sub = unsafe { Box::from_raw(subscriber) };
    let tangle_address = unsafe { Box::from_raw(announcement_link) };

    println!("Link to announcement being unwrapped: {}", tangle_address.0);

    let msg = sub.sub.send_subscribe(&tangle_address.0).unwrap();
    mem::forget(tangle_address);
    mem::forget(sub);
    Box::into_raw(Box::new(Address(msg)))
}

/// Process a keyload message 
#[no_mangle]
pub extern "C" fn sub_receive_keyload<'a>(subscriber: *mut Subscriber<&'a Client>, link: *mut Address)
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
unsafe {
        let mut sub = Box::from_raw(subscriber);

        let link = Box::from_raw(link).0;
        sub.sub.receive_keyload(&link).unwrap();
        mem::forget(sub);
        mem::forget(link);
    }
}

#[no_mangle]
pub extern "C" fn sub_receive_sequence<'a>(subscriber: *mut Subscriber<&'a Client>, link: *mut Address) -> *mut Address
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
unsafe {
        let mut sub = Box::from_raw(subscriber);

        let link = Box::from_raw(link);
        let addr = sub.sub.receive_sequence(&link.0).unwrap();
        mem::forget(sub);
        mem::forget(link);

        Box::into_raw(Box::new(Address(addr)))
    }
}

/// Process a Signed packet message 
#[no_mangle]
pub extern "C" fn sub_receive_signed_packet<'a>(subscriber: *mut Subscriber<&'a Client>, link: *mut Address) -> *mut PayloadResponse
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
unsafe {
        let mut sub = Box::from_raw(subscriber);

        let link = Box::from_raw(link);
        
        let (_signer_pk, unwrapped_public, unwrapped_masked) = sub.sub.receive_signed_packet(&link.0).unwrap();
        mem::forget(sub);
        mem::forget(link);
        
        Box::into_raw(Box::new(PayloadResponse {
            public_payload: CString::from_vec_unchecked(unwrapped_public.0).into_raw(),
            private_payload: CString::from_vec_unchecked(unwrapped_masked.0).into_raw(),
        }))
    }
}

/// Process a tagged packet message 
#[no_mangle]
pub extern "C" fn sub_receive_tagged_packet<'a>(subscriber: *mut Subscriber<&'a Client>, link: *mut Address) -> *mut PayloadResponse
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
unsafe {
        let mut sub = Box::from_raw(subscriber);

        let link = Box::from_raw(link);

        let (unwrapped_public, unwrapped_masked) = sub.sub.receive_tagged_packet(&link.0).unwrap();
        mem::forget(sub);
        mem::forget(link);

        Box::into_raw(Box::new(PayloadResponse {
            public_payload: CString::from_vec_unchecked(unwrapped_public.0).into_raw(),
            private_payload: CString::from_vec_unchecked(unwrapped_masked.0).into_raw(),
        }))
    }
}

#[no_mangle]
pub extern "C" fn sub_gen_next_msg_ids<'a>(subscriber: *mut Subscriber<&Client>) -> *mut NextMsgIds
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
    unsafe {
        let mut sub = Box::from_raw(subscriber);

        let msg_ids = sub.sub.gen_next_msg_ids(sub.sub.is_multi_branching());
        if !msg_ids.is_empty() {
            let mut ids = Vec::new();
            for msg in msg_ids {
                ids.push(NextMsgId {
                    pubkey: PubKey(msg.0),
                    seq_state: SeqState {
                        address: Address((msg.1).link),
                        state: (msg.1).seq_no as usize
                    }
                });
            }
            Box::into_raw(Box::new(NextMsgIds { ids }))
        } else {
            Box::into_raw(Box::new(NextMsgIds { ids: Vec::new() }))
        }
    }
}

#[no_mangle]
pub extern "C" fn sub_receive_msg<'a>(subscriber: *mut Subscriber<&Client>, link: *mut Address) -> *mut MsgReturn
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
    unsafe {
        let mut sub = Box::from_raw(subscriber);
        let link = Box::from_raw(link);

        let msg_return = sub.sub.receive_msg(&link.0, None).unwrap();
        mem::forget(sub);
        mem::forget(link);
        Box::into_raw(Box::new(MsgReturn(msg_return)))
    }
}

#[no_mangle]
pub extern "C" fn sub_fetch_next_msgs<'a>(subscriber: *mut Subscriber<&Client>) -> *mut MessageReturns
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
    unsafe {
        let mut sub = Box::from_raw(subscriber);

        let returns = sub.sub.fetch_next_msgs();
        mem::forget(sub);

        let mut wrapped_returns = Vec::new();
        for return_val in returns {
            wrapped_returns.push(MsgReturn(return_val));
        }
        Box::into_raw(Box::new(MessageReturns(wrapped_returns)))
    }
}

#[no_mangle]
pub extern "C" fn sub_sync_state<'a>(subscriber: *mut Subscriber<&Client>) -> *mut MessageReturns
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
    unsafe {
        let mut sub = Box::from_raw(subscriber);
        let mut returns = Vec::new();

        loop {
            let messages = sub.sub.fetch_next_msgs();
            if messages.is_empty() {
                break;
            }
            returns.extend(messages);
        }

        mem::forget(sub);

        let mut wrapped_returns = Vec::new();
        for return_val in returns {
            wrapped_returns.push(MsgReturn(return_val));
        }
        Box::into_raw(Box::new(MessageReturns(wrapped_returns)))

    }
}


