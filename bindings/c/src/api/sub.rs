use super::*;

pub type Subscriber = iota_streams::app_channels::api::tangle::Subscriber<TransportWrap>;

/// Create a new subscriber
#[no_mangle]
pub extern "C" fn sub_new(
    c_seed: *const c_char,
    c_encoding: *const c_char,
    payload_length: size_t,
    transport: *mut TransportWrap,
) -> *mut Subscriber {
    let seed = unsafe { CStr::from_ptr(c_seed).to_str().unwrap() };
    let encoding = unsafe { CStr::from_ptr(c_encoding).to_str().unwrap() };
    let tsp = unsafe { (*transport).clone() };
    let subscriber = Subscriber::new(seed, encoding, payload_length, tsp);
    Box::into_raw(Box::new(subscriber))
}

#[no_mangle]
pub extern "C" fn sub_drop(user: *mut Subscriber) {
    unsafe { Box::from_raw(user); }
}

/// Channel app instance.
#[no_mangle]
pub extern "C" fn sub_channel_address(user: *const Subscriber) -> *const ChannelAddress {
    unsafe {
        user.as_ref().map_or(null(), |user| {
            user.channel_address().map_or(null(), |channel_address| {
                channel_address as *const ChannelAddress
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_is_multi_branching(user: *const Subscriber) -> uint8_t {
    unsafe {
        user.as_ref().map_or(0, |user| {
            if user.is_multi_branching() { 1 } else { 0 }
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_get_public_key(user: *const Subscriber) -> *const PublicKey {
    unsafe {
        user.as_ref().map_or(null(), |user| {
            user.get_pk() as *const PublicKey
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_is_registered(user: *const Subscriber) -> u8 {
    unsafe {
        user.as_ref().map_or(0, |user| {
            if user.is_registered() { 1 } else { 0 }
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_unregister(user: *mut Subscriber) {
    unsafe {
        user.as_mut().map_or((), |user| {
            user.unregister();
        })
    }
}

/// Handle Channel app instance announcement.
#[no_mangle]
pub extern "C" fn sub_receive_announce(user: *mut Subscriber, link: *const Address) {
    unsafe {
        user.as_mut().map_or((), |user| {
            link.as_ref().map_or((), |link| {
                user.receive_announcement(link).unwrap(); //TODO: handle Result
            })
        })
    }
}

/// Subscribe to a Channel app instance.
#[no_mangle]
pub extern "C" fn sub_send_subscribe(user: *mut Subscriber, announcement_link: *const Address) -> *const Address {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            announcement_link.as_ref().map_or(null(), |announcement_link| {
                let link = user.send_subscribe(announcement_link).unwrap(); //TODO: handle Result
                Box::into_raw(Box::new(link))
            })
        })
    }
}

/// Process a keyload message 
#[no_mangle]
pub extern "C" fn sub_receive_keyload(user: *mut Subscriber, link: *const Address) {
    unsafe {
        user.as_mut().map_or((), |user| {
            link.as_ref().map_or((), |link| {
                user.receive_keyload(link).unwrap(); //TODO: handle Result
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_receive_sequence(user: *mut Subscriber, link: *const Address) -> *const Address {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            link.as_ref().map_or(null(), |link| {
                let seq_link = user.receive_sequence(link).unwrap(); //TODO: handle Result
                Box::into_raw(Box::new(seq_link))
            })
        })
    }
}

/// Process a Signed packet message 
#[no_mangle]
pub extern "C" fn sub_receive_signed_packet(user: *mut Subscriber, link: *const Address) -> PacketPayloads {
    unsafe {
        user.as_mut().map_or(PacketPayloads::default(), |user| {
            link.as_ref().map_or(PacketPayloads::default(), |link| {
                let signed_payloads = user.receive_signed_packet(link).unwrap(); //TODO: handle Result
                signed_payloads.into()
            })
        })
    }
}

/// Process a tagged packet message 
#[no_mangle]
pub extern "C" fn sub_receive_tagged_packet(user: *mut Subscriber, link: *const Address) -> PacketPayloads {
    unsafe {
        user.as_mut().map_or(PacketPayloads::default(), |user| {
            link.as_ref().map_or(PacketPayloads::default(), |link| {
                let payloads = user.receive_tagged_packet(link).unwrap(); //TODO: handle Result
                payloads.into()
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_gen_next_msg_ids(user: *mut Subscriber) -> *const NextMsgIds {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            let next_msg_ids = user.gen_next_msg_ids(user.is_multi_branching());
            Box::into_raw(Box::new(next_msg_ids))
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_receive_msg(user: *mut Subscriber, link: *const Address) -> *const UnwrappedMessage {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            link.as_ref().map_or(null(), |link| {
                let u = user.receive_msg(link, None).unwrap(); //TODO: handle Result
                Box::into_raw(Box::new(u))
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_fetch_next_msgs(user: *mut Subscriber) -> *const UnwrappedMessages {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            let m = user.fetch_next_msgs();
            Box::into_raw(Box::new(m))
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_sync_state(user: *mut Subscriber) -> *const UnwrappedMessages {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            let mut ms = Vec::new();
            loop {
                let m = user.fetch_next_msgs();
                if m.is_empty() {
                    break;
                }
                ms.extend(m);
            }
            Box::into_raw(Box::new(ms))
        })
    }
}
