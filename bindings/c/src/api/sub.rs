use super::*;

pub type Subscriber = iota_streams::app_channels::api::tangle::Subscriber<TransportWrap>;

/// Create a new subscriber
#[no_mangle]
pub extern "C" fn sub_new(
    c_seed: *const c_char,
    transport: *mut TransportWrap,
) -> *mut Subscriber {
    let seed = unsafe { CStr::from_ptr(c_seed).to_str().unwrap() };
    let tsp = unsafe { (*transport).clone() };
    let subscriber = Subscriber::new(seed, tsp);
    Box::into_raw(Box::new(subscriber))
}

/// Recover an existing channel from seed and existing announcement message
#[no_mangle]
pub extern "C" fn sub_recover(
    c_seed: *const c_char,
    c_ann_address: *const Address,
    transport: *mut TransportWrap
) -> *mut Subscriber {
    unsafe {
        c_ann_address.as_ref().map_or(null_mut(), |addr| {
            let seed = CStr::from_ptr(c_seed).to_str().unwrap();
            let tsp = (*transport).clone();
            Subscriber::recover(seed, addr, tsp)
                .map_or(null_mut(), |sub| {
                    Box::into_raw(Box::new(sub))
                })
        })
    }
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

#[no_mangle]
pub extern "C" fn sub_send_tagged_packet(
    user: *mut Subscriber,
    link_to: MessageLinks,
    public_payload_ptr: *const uint8_t,
    public_payload_size: size_t,
    masked_payload_ptr: *const uint8_t,
    masked_payload_size: size_t,
) -> MessageLinks {
    unsafe {
        user.as_mut().map_or(MessageLinks::default(), |user| {
            link_to
                .into_seq_link(user.is_multi_branching())
                .map_or(MessageLinks::default(), |link_to| {
                    let public_payload = Bytes(Vec::from_raw_parts(
                        public_payload_ptr as *mut u8,
                        public_payload_size,
                        public_payload_size,
                    ));
                    let masked_payload = Bytes(Vec::from_raw_parts(
                        masked_payload_ptr as *mut u8,
                        masked_payload_size,
                        masked_payload_size,
                    ));
                    let response = user
                        .send_tagged_packet(link_to, &public_payload, &masked_payload)
                        .unwrap();
                    let _ = core::mem::ManuallyDrop::new(public_payload.0);
                    let _ = core::mem::ManuallyDrop::new(masked_payload.0);
                    response.into()
                })
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_send_signed_packet(
    user: *mut Subscriber,
    link_to: MessageLinks,
    public_payload_ptr: *const uint8_t,
    public_payload_size: size_t,
    masked_payload_ptr: *const uint8_t,
    masked_payload_size: size_t,
) -> MessageLinks {
    unsafe {
        user.as_mut().map_or(MessageLinks::default(), |user| {
            link_to
                .into_seq_link(user.is_multi_branching())
                .map_or(MessageLinks::default(), |link_to| {
                    let public_payload = Bytes(Vec::from_raw_parts(
                        public_payload_ptr as *mut u8,
                        public_payload_size,
                        public_payload_size,
                    ));
                    let masked_payload = Bytes(Vec::from_raw_parts(
                        masked_payload_ptr as *mut u8,
                        masked_payload_size,
                        masked_payload_size,
                    ));
                    let response = user
                        .send_signed_packet(link_to, &public_payload, &masked_payload)
                        .unwrap();
                    let _ = core::mem::ManuallyDrop::new(public_payload.0);
                    let _ = core::mem::ManuallyDrop::new(masked_payload.0);
                    response.into()
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
pub extern "C" fn sub_receive_keyload_from_ids(user: *mut Subscriber, next_msg_ids: *const NextMsgIds) -> *const MessageLinks {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            next_msg_ids.as_ref().map_or(null(), |ids| {
                for (_pk, cursor) in ids {
                    let keyload_link = user.receive_sequence(&cursor.link);
                    if keyload_link.is_ok() {
                        let keyload_link = keyload_link.unwrap();
                        if user.receive_keyload(&keyload_link).unwrap() {
                            return Box::into_raw(Box::new(MessageLinks {
                                msg_link: Box::into_raw(Box::new(cursor.link.clone())),
                                seq_link: Box::into_raw(Box::new(keyload_link))
                            }))
                        }
                    }
                }
                null()
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_receive_msg(user: *mut Subscriber, link: *const Address) -> *const UnwrappedMessage {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            link.as_ref().map_or(null(), |link| {
                let u = user.receive_msg(link).unwrap(); //TODO: handle Result
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
pub extern "C" fn sub_fetch_prev_msg(user: *mut Subscriber, address: *const Address) -> *const UnwrappedMessage {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            address.as_ref().map_or(null(), |addr| {
                let m = user.fetch_prev_msg(addr).unwrap();
                Box::into_raw(Box::new(m))
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_fetch_prev_msgs(user: *mut Subscriber, address: *const Address, num_msgs: size_t) -> *const UnwrappedMessages {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            address.as_ref().map_or(null(), |addr| {
                let m = user.fetch_prev_msgs(addr, num_msgs).unwrap();
                Box::into_raw(Box::new(m))
            })
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

#[no_mangle]
pub extern "C" fn sub_fetch_state(user: *mut Subscriber) -> *const UserState {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            user.fetch_state().map_or(null(), |state| {
                Box::into_raw(Box::new(state))
            })
        })
    }
}
