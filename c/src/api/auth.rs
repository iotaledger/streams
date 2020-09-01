use crate::{AppInst, MsgId, Address, Author, Message, PskIds, PubKey, PubKeyWrap, SeqState, NextMsgId, Transport, Preparsed, KePks, MWM, send_message};

use iota_streams::app_channels::api::tangle::{Author as Auth, Transport as Trans};
use iota_streams::app::transport::{
    tangle::{
        TangleAddress,
        AppInst as ApplicationInstance,
        MsgId as MessageIdentifier,
    }
};
use std::ffi::CStr;
use std::os::raw::{c_char, c_ulonglong};
use iota::client::Client;
use crate::constants::*;
use std::ops::Deref;


/// Generate a new Author Instance
#[no_mangle]
pub extern "C" fn auth_new(seed: *const c_char , encoding: *const c_char, payload_length: *const c_ulonglong, multi_branching: bool) -> *mut Author {
    let c_seed = unsafe {
        CStr::from_ptr(seed)
    };

    let c_encoding = unsafe {
        CStr::from_ptr(encoding)
    };

    let mut client = Client::get();
    println!("Added node: {}", Client::add_node(URL).unwrap());
    let auth = Auth::new(c_seed.to_str().unwrap(), c_encoding.to_str().unwrap(), payload_length as usize, multi_branching);

    Box::into_raw(Box::new(Author{ auth }))
}


#[no_mangle]
pub extern "C" fn init_transport<'a>() -> *mut Transport<'a> {
    unsafe {
        let mut client = Client::get();
        Client::add_node(URL);
        Box::into_raw(Box::new(Transport(client)))
    }
}


/*
fn make_auth(auth: Auth, transport: &mut T) -> Author
where
    T::SendOptions: Default,
{
    Author {
        auth: auth,
        transport: transport,
    }
}*/


/// Channel app instance.
#[no_mangle]
pub extern "C" fn auth_channel_address(author: *mut Author) -> *mut AppInst {
    unsafe {
        let auth = Box::from_raw(author);
        let appinst = AppInst(auth.auth.channel_address().clone());
        println!("\nApplication Instance: {}", appinst.0);
        Box::into_raw(Box::new(appinst))
    }
}

/// Announce creation of a new Channel.
#[no_mangle]
pub extern "C" fn auth_announce(author: *mut Author) -> *mut Address {
    let raw: *mut Address;

    let mut auth = unsafe {
        Box::from_raw(author)
    };

    let msg = auth.auth.announce().unwrap();
    let mut client = Client::get();

    println!("Sending Announcement...\n");
    send_message(&mut client, &Message(msg.clone()));
    println!("Announcement sent... Boxing Address...\n");
    Box::into_raw(Box::new(Address(msg.link)))
}

/// Create a new keyload for a list of subscribers.
#[no_mangle]
pub extern "C" fn auth_share_keyload(author: *mut Author,  link_to: *mut Address, psk_ids: *mut PskIds, ke_pks: *mut KePks) -> Vec<*mut Address> {
    unsafe {
        let mut auth = Box::from_raw(author);
        let unboxed_link = Box::from_raw(link_to);
        let tangle_address = &TangleAddress::new(unboxed_link.0.appinst.clone(), unboxed_link.0.msgid.clone());
        let unboxed_psk_ids = Box::from_raw(psk_ids);
        let unboxed_ke_pks  = Box::from_raw(ke_pks);
        let response = auth.auth.share_keyload(tangle_address, &unboxed_psk_ids.0, &unboxed_ke_pks.0).unwrap();

        let mut msgs = Vec::with_capacity(2);
        msgs.push(Message(response.0));
        if response.1.is_some() {
            msgs.push(Message(response.1.unwrap()))
        }

        let mut msg_links = Vec::with_capacity(2);
        for msg in msgs {
            let msg_link = Address(msg.0.clone().link);
            send_message(&mut Client::get(), &msg);
            println!("Link for message: {:?}", msg_link.0.msgid);
            msg_links.push(Box::into_raw(Box::new(msg_link)));
        }
        msg_links
    }
}

/// Create keyload for all subscribed subscribers.
#[no_mangle]
pub extern "C" fn auth_share_keyload_for_everyone(author: *mut Author, link_to: *mut Address) -> Vec<*mut Address> {
    unsafe {
        let mut auth = Box::from_raw(author);
        let unboxed_link = Box::from_raw(link_to);
        let tangle_address = TangleAddress::new(ApplicationInstance::from(unboxed_link.0.appinst), MessageIdentifier::from(unboxed_link.0.msgid));
        println!("Tangle address: {}\n", tangle_address);
        let response = auth.auth.share_keyload_for_everyone(&tangle_address);
        let response2 = auth.auth.share_keyload_for_everyone(&tangle_address);
        println!("Responded");
        if response2.is_err() {
            println!("Response error: {}", response2.err().unwrap());
        }

        let response = response.unwrap();

        let mut msgs = Vec::with_capacity(2);
        msgs.push(Message(response.0));
        if response.1.is_some() {
            msgs.push(Message(response.1.unwrap()))
        }

        let mut msg_links = Vec::with_capacity(2);
        for msg in msgs {
            let msg_link = Address(msg.0.clone().link);
            send_message(&mut Client::get(), &msg);
            println!("Link for message: {}", msg_link.0.msgid);
            msg_links.push(Box::into_raw(Box::new(msg_link)));
        }
        msg_links
    }
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