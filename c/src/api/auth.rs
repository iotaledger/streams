//use crate::{AppInst, MsgId, Address, Author, Message, PskIds, PubKey, PubKeyWrap, SeqState, NextMsgId, Transport, Preparsed, KePks, MWM, send_message, MessageLinks};
use crate::{AppInst, Address, Author, Message, PskIds, KePks, send_message, MessageLinks};

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
    send_message(&mut client, &Message(msg.clone()));
    Box::into_raw(Box::new(Address(msg.link)))
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
        send_and_retrieve_links(response)
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

        send_and_retrieve_links(response)
    }
}


#[no_mangle]
pub extern "C" fn auth_tag_packet(author: *mut Author, link_to: *mut MessageLinks, public_payload_ptr: *const c_char, private_payload_ptr: *const c_char) -> *mut MessageLinks {
    unsafe {
        let mut auth = Box::from_raw(author);
        let unboxed_link = Box::from_raw(link_to);

        let tangle_address = get_seq_link(unboxed_link, auth.auth.get_branching_flag() == 1);
        let public_payload = CStr::from_ptr(public_payload_ptr);
        let private_payload = CStr::from_ptr(private_payload_ptr);

        println!("Tangle address: {}\n", tangle_address);
        let response = auth.auth.tag_packet(&tangle_address, &Bytes(public_payload.to_bytes().to_vec()), &Bytes(private_payload.to_bytes().to_vec())).unwrap();
        mem::forget(auth);

        send_and_retrieve_links(response)
    }
}

#[no_mangle]
pub extern "C" fn auth_sign_packet(author: *mut Author, link_to: *mut MessageLinks, public_payload_ptr: *const c_char, private_payload_ptr: *const c_char) -> *mut MessageLinks {
    unsafe {
        let mut auth = Box::from_raw(author);
        let unboxed_link = Box::from_raw(link_to);

        let tangle_address = get_seq_link(unboxed_link, auth.auth.get_branching_flag() == 1);
        let public_payload = CStr::from_ptr(public_payload_ptr);
        let private_payload = CStr::from_ptr(private_payload_ptr);

        let response = auth.auth.sign_packet(&tangle_address, &Bytes(public_payload.to_bytes().to_vec()), &Bytes(private_payload.to_bytes().to_vec())).unwrap();
        mem::forget(auth);

        send_and_retrieve_links(response)
    }
}



fn get_seq_link(unboxed_link: Box<MessageLinks>, branching: bool) -> TangleAddress {
    let link = if !branching {
        unboxed_link.msg_link.0
    } else {
        unboxed_link.seq_link.unwrap().0
    };

    TangleAddress::new(
        ApplicationInstance::from(link.appinst.clone()),
        MessageIdentifier::from(link.msgid.clone())
    )
}


fn send_and_retrieve_links(response: (TangleMessage, Option<TangleMessage>)) -> *mut MessageLinks {
    let mut msgs = Vec::with_capacity(2);
    msgs.push(Message(response.0));
    if response.1.is_some() {
        msgs.push(Message(response.1.unwrap()))
    }

    for msg in &msgs {
        let msg_link = Address(msg.0.clone().link);
        print!("Sending Message... ");
        send_message(&mut Client::get(), &msg);
        println!("Link for message: {}", msg_link.0.msgid);
    }

    let msg_links = if msgs.len() < 2 {
        MessageLinks {
            msg_link: Address(msgs.get(0).unwrap().0.link.clone()),
            seq_link: None
        }
    } else {
        MessageLinks {
            msg_link: Address(msgs.get(0).unwrap().0.link.clone()),
            seq_link: Some(Address(msgs.get(1).unwrap().0.link.clone()))
        }
    };
    Box::into_raw(Box::new(msg_links))

}


/*
#[no_mangle]
pub extern "C" fn void auth_store_state(Author *author, PubKey *pk, Address *link);

#[no_mangle]
pub extern "C" fn void auth_store_state_for_all(Author *author, Address *link, size_t seq_num);

#[no_mangle]
pub extern "C" fn SeqState auth_get_seq_state(Author *author, PubKey *pk);

/// Create a signed packet.
#[no_mangle]
pub extern "C" fn Message[2] auth_sign_packet(Author *author, Address *link_to, Bytes *public_payload, Bytes *masked_payload);

/// Create a tagged packet.
#[no_mangle]
pub extern "C" fn Message[2] auth_tag_packet(Author *author, Address *link_to, Bytes *public_payload, Bytes *masked_payload);

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