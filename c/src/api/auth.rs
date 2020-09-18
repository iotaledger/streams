//use crate::{AppInst, MsgId, Address, Author, Message, PskIds, PubKey, PubKeyWrap, SeqState, NextMsgId, Transport, Preparsed, KePks, MWM, send_message, MessageLinks};
use crate::{AppInst, Address, Author, Message, PskIds, KePks, MessageLinks, SeqState, Preparsed, utils, client};

use iota_streams::app_channels::api::tangle::{Author as Auth, Message as TangleMessage};
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
use std::os::raw::{c_char, c_ulonglong};
use iota::client::Client;
use crate::constants::*;


/// Generate a new Author Instance
#[no_mangle]
pub extern "C" fn auth_new(seed: *const c_char , encoding: *const c_char, payload_length: *const c_ulonglong, multi_branching: bool) -> *mut Author {
    let c_seed = unsafe {
        CStr::from_ptr(seed)
    };

    let c_encoding = unsafe {
        CStr::from_ptr(encoding)
    };

    Client::get();
    Client::add_node(URL).unwrap();
    let auth = Auth::new(c_seed.to_str().unwrap(), c_encoding.to_str().unwrap(), payload_length as usize, multi_branching);

    Box::into_raw(Box::new(Author{ auth }))
}


/// Channel app instance.
#[no_mangle]
pub extern "C" fn auth_channel_address(author: *mut Author) -> *mut AppInst {
    unsafe {
        let auth = Box::from_raw(author);
        let appinst = AppInst(auth.auth.channel_address().clone());
        mem::forget(auth);
        Box::into_raw(Box::new(appinst))
    }
}

/// Announce creation of a new Channel.
#[no_mangle]
pub extern "C" fn auth_announce(author: *mut Author) -> *mut Address {
    let mut auth = unsafe { Box::from_raw(author) };

    let msg = auth.auth.announce().unwrap();
    mem::forget(auth);

    let mut client = Client::get();
    client::send_message(&mut client, &Message(msg.clone()));
    Box::into_raw(Box::new(Address(msg.link)))
}

#[no_mangle]
pub extern "C" fn auth_get_branching_flag(author: *mut Author) -> u8 {
    unsafe {
        let auth = Box::from_raw(author);
        let branching = auth.auth.get_branching_flag();
        mem::forget(auth);

        branching
    }
}

/// unwrap and add a subscriber to the list of subscribers
#[no_mangle]
pub extern "C" fn auth_unwrap_subscribe(author: *mut Author, message: *mut TangleMessage){
    unsafe {
        let mut auth = Box::from_raw(author);
        let msg = Box::from_raw(message);

        let parsed = msg.parse_header();
        auth.auth.unwrap_subscribe(parsed.unwrap()).unwrap();
        
        mem::forget(auth);
        mem::forget(msg);
    }
}

/// Create a new keyload for a list of subscribers.
#[no_mangle]
pub extern "C" fn auth_share_keyload(author: *mut Author,  link_to: *mut Address, psk_ids: *mut PskIds, ke_pks: *mut KePks) -> *mut MessageLinks {
    unsafe {
        let mut auth = Box::from_raw(author);
        let unboxed_link = Box::from_raw(link_to);
        let tangle_address = &TangleAddress::new(unboxed_link.0.appinst.clone(), unboxed_link.0.msgid.clone());
        let unboxed_psk_ids = Box::from_raw(psk_ids);
        let unboxed_ke_pks  = Box::from_raw(ke_pks);

        println!("Tangle address: {}\n", tangle_address);
        let response = auth.auth.share_keyload(tangle_address, &unboxed_psk_ids.0, &unboxed_ke_pks.0).unwrap();
        mem::forget(auth);
        utils::send_and_retrieve_links(response)
    }
}

/// Create keyload for all subscribed subscribers.
#[no_mangle]
pub extern "C" fn auth_share_keyload_for_everyone(author: *mut Author, link_to: *mut Address) -> *mut MessageLinks {
    unsafe {
        let mut auth = Box::from_raw(author);
        let unboxed_link = Box::from_raw(link_to);
        let tangle_address = TangleAddress::new(ApplicationInstance::from(unboxed_link.0.appinst.clone()), MessageIdentifier::from(unboxed_link.0.msgid.clone()));

        println!("Tangle address: {}\n", tangle_address);
        let response = auth.auth.share_keyload_for_everyone(&tangle_address).unwrap();
        mem::forget(auth);

        utils::send_and_retrieve_links(response)
    }
}


#[no_mangle]
pub extern "C" fn auth_tag_packet(author: *mut Author, link_to: *mut MessageLinks, public_payload_ptr: *const c_char, private_payload_ptr: *const c_char) -> *mut MessageLinks {
    unsafe {
        let mut auth = Box::from_raw(author);
        let unboxed_link = Box::from_raw(link_to);

        let tangle_address = utils::get_seq_link(unboxed_link, auth.auth.get_branching_flag() == 1);
        let public_payload = CStr::from_ptr(public_payload_ptr);
        let private_payload = CStr::from_ptr(private_payload_ptr);

        println!("Tangle address: {}\n", tangle_address);
        let response = auth.auth.tag_packet(&tangle_address, &Bytes(public_payload.to_bytes().to_vec()), &Bytes(private_payload.to_bytes().to_vec())).unwrap();
        mem::forget(auth);

        utils::send_and_retrieve_links(response)
    }
}

#[no_mangle]
pub extern "C" fn auth_sign_packet(author: *mut Author, link_to: *mut MessageLinks, public_payload_ptr: *const c_char, private_payload_ptr: *const c_char) -> *mut MessageLinks {
    unsafe {
        let mut auth = Box::from_raw(author);
        let unboxed_link = Box::from_raw(link_to);

        let tangle_address = utils::get_seq_link(unboxed_link, auth.auth.get_branching_flag() == 1);
        let public_payload = CStr::from_ptr(public_payload_ptr);
        let private_payload = CStr::from_ptr(private_payload_ptr);

        let response = auth.auth.sign_packet(&tangle_address, &Bytes(public_payload.to_bytes().to_vec()), &Bytes(private_payload.to_bytes().to_vec())).unwrap();
        mem::forget(auth);

        utils::send_and_retrieve_links(response)
    }
}




#[no_mangle]
pub extern "C" fn auth_fetch_next_transaction(author: *mut Author) -> *mut Message {
    unsafe {
        let mut auth = Box::from_raw(author);

        let branching = auth.auth.get_branching_flag() == 1_u8;
        let response = auth.auth.gen_next_msg_ids(branching.clone());

        for link in response {
            let msg = client::recv_message(&mut Client::get(), &Address(link.1.clone()));
            if msg.is_some() {
                let response = msg.unwrap();
                println!("Found message: {:?}", &response.0.link);
                if branching {
                    auth.auth.store_state(link.0, link.1);
                } else {
                    auth.auth.store_state_for_all(link.1, link.2);
                }
                mem::forget(auth);
                return Box::into_raw(Box::new(response))
            }
        }

        println!("No new messages found...");
        mem::forget(auth);
        std::ptr::null_mut()
    }
}








/*
#[no_mangle]
pub extern "C" fn void auth_store_state(Author *author, PubKey *pk, Address *link);

#[no_mangle]
pub extern "C" fn void auth_store_state_for_all(Author *author, Address *link, size_t seq_num);


/// Unwrap tagged packet.
#[no_mangle]
pub extern "C" fn Bytes[2] auth_unwrap_tagged_packet(Author *author, Preparsed *preparsed);

/// Subscribe a new subscriber.
#[no_mangle]
pub extern "C" fn void auth_unwrap_subscribe(Author *author, Preparsed *preparsed);

#[no_mangle]
pub extern "C" fn Address auth_unwrap_sequence(Author *author, Preparsed *preparsed);

#[no_mangle]
pub extern "C" fn char auth_get_branching_flag(Author *author);

#[no_mangle]
pub extern "C" fn Address auth_gen_msg_id(Author *author, Address *link, PubKey *pk, size_t seq);

#[no_mangle]
pub extern "C" fn NextMsgId[] auth_gen_next_msg_ids(&mut self, branching: bool);
*/