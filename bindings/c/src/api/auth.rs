//use crate::{AppInst, MsgId, Address, Author, Message, PskIds, PubKey, PubKeyWrap, SeqState, NextMsgId, Transport, Preparsed, KePks, MWM, send_message, MessageLinks};
use crate::{AppInst, Address, Author, PskIds, KePks, MessageLinks, PayloadResponse, utils, MessageReturns, retrieve_links, PubKey, NextMsgId, NextMsgIds, SeqState, MsgReturn};

use iota_streams::{
    app_channels::api::{
        tangle::{Author as Auth, Address as TangleAddress, Message as TangleMessage},
    },
    app::transport::Transport,
    core::prelude::Vec,
};
use iota_streams::ddml::types::Bytes;

use std::mem;
use std::ffi::CString;
use std::ffi::CStr;
use std::os::raw::{c_char, c_ulonglong};
use iota::client::Client;
use crate::constants::*;


/// Generate a new Author Instance
#[no_mangle]
pub extern "C" fn auth_new<'a>(seed: *const c_char , encoding: *const c_char, payload_length: *const c_ulonglong, multi_branching: bool) -> *mut Author<&'a Client> {
    let c_seed = unsafe {
        CStr::from_ptr(seed)
    };

    let c_encoding = unsafe {
        CStr::from_ptr(encoding)
    };

    let client = Client::get();
    Client::add_node(URL).unwrap();
    let auth: Auth<&Client> = Auth::new(c_seed.to_str().unwrap(), c_encoding.to_str().unwrap(), payload_length as usize, multi_branching, client);

    Box::into_raw(Box::new(Author{ auth }))
}

/// Channel app instance.
#[no_mangle]
pub extern "C" fn auth_channel_address<'a>(author: *mut Author<&'a Client>) -> *mut AppInst
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
    unsafe {
        let auth = Box::from_raw(author);
        if let Some(channel_address) = auth.auth.channel_address() {
            let appinst = AppInst(channel_address.clone());
            mem::forget(auth);
            Box::into_raw(Box::new(appinst))
        } else {
            std::ptr::null_mut()
        }
    }
}

/// Announce creation of a new Channel.
#[no_mangle]
pub extern "C" fn auth_send_announce<'a>(author: *mut Author<&'a Client>) -> *mut Address
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
let mut auth = unsafe { Box::from_raw(author) };

    let msg = auth.auth.send_announce().unwrap();
    mem::forget(auth);
    Box::into_raw(Box::new(Address(msg)))
}

#[no_mangle]
pub extern "C" fn auth_get_branching_flag<'a>(author: *mut Author<&'a Client>) -> u8
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
unsafe {
        let auth = Box::from_raw(author);
        let branching = if auth.auth.is_multi_branching() { 1 } else { 0 };
        mem::forget(auth);

        branching
    }
}

#[no_mangle]
pub extern "C" fn auth_get_pk<'a> (author: *mut Author<&'a Client>) -> *mut PubKey
where
    <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
    <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
    unsafe {
        let auth = Box::from_raw(author);
        let pk = auth.auth.get_pk().clone();
        mem::forget(auth);
        Box::into_raw(Box::new(PubKey(pk)))
    }

}

/// unwrap and add a subscriber to the list of subscribers
#[no_mangle]
pub extern "C" fn auth_receive_subscribe<'a>(author: *mut Author<&'a Client>, link: *mut Address)
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
unsafe {
        let mut auth = Box::from_raw(author);
        let link = Box::from_raw(link);

        auth.auth.receive_subscribe(&link.0).unwrap();
        
        mem::forget(auth);
        mem::forget(link);
    }
}

/// Create a new keyload for a list of subscribers.
#[no_mangle]
pub extern "C" fn auth_send_keyload<'a>(author: *mut Author<&'a Client>,  link_to: *mut Address, psk_ids: *mut PskIds, ke_pks: *mut KePks) -> *mut MessageLinks
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
unsafe {
        let mut auth = Box::from_raw(author);
        let tangle_address = Box::from_raw(link_to);
        let unboxed_psk_ids = Box::from_raw(psk_ids);
        let unboxed_ke_pks  = Box::from_raw(ke_pks);

        println!("Tangle address: {}\n", tangle_address.0);
        let response = auth.auth.send_keyload(&tangle_address.0, &unboxed_psk_ids.0, &unboxed_ke_pks.0).unwrap();
        mem::forget(auth);
        retrieve_links(response)
    }
}

/// Create keyload for all subscribed subscribers.
#[no_mangle]
pub extern "C" fn auth_send_keyload_for_everyone<'a>(author: *mut Author<&'a Client>, link_to: *mut Address) -> *mut MessageLinks
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
unsafe {
        let mut auth = Box::from_raw(author);
        let tangle_address = Box::from_raw(link_to);

        println!("Tangle address: {}\n", tangle_address.0);
        let response = auth.auth.send_keyload_for_everyone(&tangle_address.0).unwrap();
        mem::forget(auth);
        retrieve_links(response)
    }
}


#[no_mangle]
pub extern "C" fn auth_send_tagged_packet<'a>(author: *mut Author<&'a Client>, link_to: *mut MessageLinks, public_payload_ptr: *const c_char, private_payload_ptr: *const c_char) -> *mut MessageLinks
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
unsafe {
        let mut auth = Box::from_raw(author);
        let unboxed_link = Box::from_raw(link_to);

        let tangle_address = utils::get_seq_link(unboxed_link, auth.auth.is_multi_branching());
        let public_payload = CStr::from_ptr(public_payload_ptr);
        let private_payload = CStr::from_ptr(private_payload_ptr);

        println!("Tangle address: {}\n", tangle_address);
        let response = auth.auth.send_tagged_packet(&tangle_address, &Bytes(public_payload.to_bytes().to_vec()), &Bytes(private_payload.to_bytes().to_vec())).unwrap();
        mem::forget(auth);
        retrieve_links(response)
    }
}

#[no_mangle]
pub extern "C" fn auth_receive_tagged_packet<'a>(author: *mut Author<&'a Client>, link: *mut Address) -> *mut PayloadResponse
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
unsafe {
        let mut auth = Box::from_raw(author);

        let link = Box::from_raw(link);
        let (unwrapped_public, unwrapped_masked) = auth.auth.receive_tagged_packet(&link.0).unwrap();
        mem::forget(auth);
        mem::forget(link);

        Box::into_raw(Box::new(PayloadResponse {
            public_payload: CString::from_vec_unchecked(unwrapped_public.0).into_raw(),
            private_payload: CString::from_vec_unchecked(unwrapped_masked.0).into_raw(),
        }))
    }
}

/// Process a Signed packet message
#[no_mangle]
pub extern "C" fn auth_receive_signed_packet<'a>(auth: *mut Author<&'a Client>, link: *mut Address) -> *mut PayloadResponse
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
    unsafe {
        let mut auth = Box::from_raw(auth);

        let link = Box::from_raw(link);

        let (_signer_pk, unwrapped_public, unwrapped_masked) = auth.auth.receive_signed_packet(&link.0).unwrap();
        mem::forget(auth);
        mem::forget(link);

        Box::into_raw(Box::new(PayloadResponse {
            public_payload: CString::from_vec_unchecked(unwrapped_public.0).into_raw(),
            private_payload: CString::from_vec_unchecked(unwrapped_masked.0).into_raw(),
        }))
    }
}

#[no_mangle]
pub extern "C" fn auth_receive_sequence<'a>(author: *mut Author<&'a Client>, link: *mut Address) -> *mut Address
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
unsafe {
        let mut auth = Box::from_raw(author);

        let link = Box::from_raw(link);
        let msg_link = auth.auth.receive_sequence(&link.0).unwrap();
        mem::forget(auth);
        mem::forget(link);
        Box::into_raw(Box::new(Address(msg_link)))
    }
}

#[no_mangle]
pub extern "C" fn auth_send_signed_packet<'a>(author: *mut Author<&'a Client>, link_to: *mut MessageLinks, public_payload_ptr: *const c_char, private_payload_ptr: *const c_char) -> *mut MessageLinks
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
unsafe {
        let mut auth = Box::from_raw(author);
        let unboxed_link = Box::from_raw(link_to);

        let tangle_address = utils::get_seq_link(unboxed_link, auth.auth.is_multi_branching());
        let public_payload = CStr::from_ptr(public_payload_ptr);
        let private_payload = CStr::from_ptr(private_payload_ptr);

        let response = auth.auth.send_signed_packet(&tangle_address, &Bytes(public_payload.to_bytes().to_vec()), &Bytes(private_payload.to_bytes().to_vec())).unwrap();
        mem::forget(auth);
        retrieve_links(response)
    }
}

#[no_mangle]
pub extern "C" fn auth_gen_next_msg_ids<'a>(author: *mut Author<&Client>) -> *mut NextMsgIds
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
    unsafe {
        let mut auth = Box::from_raw(author);
        let msg_ids = auth.auth.gen_next_msg_ids(auth.auth.is_multi_branching());
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
pub extern "C" fn auth_receive_msg<'a>(author: *mut Author<&Client>, link: *mut Address) -> *mut MsgReturn
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
    unsafe {
        let mut auth = Box::from_raw(author);
        let link = Box::from_raw(link);

        let msg_return = auth.auth.receive_msg(&link.0, None).unwrap();
        mem::forget(auth);
        mem::forget(link);
        Box::into_raw(Box::new(MsgReturn(msg_return)))
    }
}


#[no_mangle]
pub extern "C" fn auth_fetch_next_msgs<'a>(author: *mut Author<&Client>) -> *mut MessageReturns
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
unsafe {
        let mut auth = Box::from_raw(author);

        let returns = auth.auth.fetch_next_msgs();
        mem::forget(auth);

        let mut wrapped_returns = Vec::new();
        for return_val in returns {
            wrapped_returns.push(MsgReturn(return_val));
        }
        Box::into_raw(Box::new(MessageReturns(wrapped_returns)))
    }
}

#[no_mangle]
pub extern "C" fn auth_sync_state<'a>(auth: *mut Author<&Client>) -> *mut MessageReturns
    where
        <&'a Client as Transport<TangleAddress, TangleMessage>>::RecvOptions: Default + Copy,
        <&'a Client as Transport<TangleAddress, TangleMessage>>::SendOptions: Default + Copy,
{
    unsafe {
        let mut auth = Box::from_raw(auth);
        let mut returns = Vec::new();

        loop {
            let messages = auth.auth.fetch_next_msgs();
            if messages.is_empty() {
                break;
            }
            returns.extend(messages);
        }

        mem::forget(auth);

        let mut wrapped_returns = Vec::new();
        for return_val in returns {
            wrapped_returns.push(MsgReturn(return_val));
        }
        Box::into_raw(Box::new(MessageReturns(wrapped_returns)))

    }
}