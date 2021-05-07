use super::*;

pub type Author = iota_streams::app_channels::api::tangle::Author<TransportWrap>;

/// Generate a new Author Instance
#[no_mangle]
pub extern "C" fn auth_new(
    c_seed: *const c_char,
    c_encoding: *const c_char,
    payload_length: size_t,
    multi_branching: uint8_t,
    transport: *mut TransportWrap,
) -> *mut Author {
    let seed = unsafe { CStr::from_ptr(c_seed).to_str().unwrap() };
    let encoding = unsafe { CStr::from_ptr(c_encoding).to_str().unwrap() };
    let tsp = unsafe { (*transport).clone() };
    let user = Author::new(seed, encoding, payload_length, multi_branching != 0, tsp);
    Box::into_raw(Box::new(user))
}

/// Recover an existing channel from seed and existing announcement message
#[no_mangle]
pub extern "C" fn auth_recover(
    c_seed: *const c_char,
    c_ann_address: *const Address,
    multi_branching: uint8_t,
    transport: *mut TransportWrap
) -> *mut Author {
    unsafe {
        c_ann_address.as_ref().map_or(null_mut(), |addr| {
            let seed = CStr::from_ptr(c_seed).to_str().unwrap();
            let tsp = (*transport).clone();
            Author::recover(seed, addr, multi_branching != 0, tsp)
                .map_or(null_mut(), |auth| {
                    Box::into_raw(Box::new(auth))
                })
        })
    }
}


#[no_mangle]
pub extern "C" fn auth_drop(user: *mut Author) {
    unsafe {
        Box::from_raw(user);
    }
}

/// Channel app instance.
#[no_mangle]
pub extern "C" fn auth_channel_address(user: *const Author) -> *const ChannelAddress {
    unsafe {
        user.as_ref().map_or(null(), |user| {
            user.channel_address()
                .map_or(null(), |channel_address| channel_address as *const ChannelAddress)
        })
    }
}

#[no_mangle]
pub extern "C" fn auth_is_multi_branching(user: *const Author) -> uint8_t {
    unsafe {
        user.as_ref()
            .map_or(0, |user| if user.is_multi_branching() { 1 } else { 0 })
    }
}

#[no_mangle]
pub extern "C" fn auth_get_public_key(user: *const Author) -> *const PublicKey {
    unsafe { user.as_ref().map_or(null(), |user| user.get_pk() as *const PublicKey) }
}

/// Announce creation of a new Channel.
#[no_mangle]
pub extern "C" fn auth_send_announce(user: *mut Author) -> *const Address {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            user.send_announce().map_or(null(), |a| Box::into_raw(Box::new(a)))
        })
    }
}

/// unwrap and add a subscriber to the list of subscribers
#[no_mangle]
pub extern "C" fn auth_receive_subscribe(user: *mut Author, link: *const Address) {
    unsafe {
        user.as_mut().map_or((), |user| {
            link.as_ref().map_or((), |link| {
                user.receive_subscribe(link).unwrap(); // TODO: handle Result
            })
        })
    }
}

/// Create a new keyload for a list of subscribers.
#[no_mangle]
pub extern "C" fn auth_send_keyload(
    user: *mut Author,
    link_to: *const Address,
    psk_ids: *const PskIds,
    ke_pks: *const KePks,
) -> MessageLinks {
    unsafe {
        user.as_mut().map_or(MessageLinks::default(), |user| {
            link_to.as_ref().map_or(MessageLinks::default(), |link_to| {
                psk_ids.as_ref().map_or(MessageLinks::default(), |psk_ids| {
                    ke_pks.as_ref().map_or(MessageLinks::default(), |ke_pks| {
                        let response = user.send_keyload(link_to, psk_ids, ke_pks).unwrap();
                        response.into()
                    })
                })
            })
        })
    }
}

/// Create keyload for all subscribed subscribers.
#[no_mangle]
pub extern "C" fn auth_send_keyload_for_everyone(user: *mut Author, link_to: *const Address) -> MessageLinks {
    unsafe {
        user.as_mut().map_or(MessageLinks::default(), |user| {
            link_to.as_ref().map_or(MessageLinks::default(), |link_to| {
                let response = user.send_keyload_for_everyone(link_to).unwrap();
                response.into()
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn auth_send_tagged_packet(
    user: *mut Author,
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
pub extern "C" fn auth_receive_tagged_packet(user: *mut Author, link: *const Address) -> PacketPayloads {
    unsafe {
        user.as_mut().map_or(PacketPayloads::default(), |user| {
            link.as_ref().map_or(PacketPayloads::default(), |link| {
                let payloads = user.receive_tagged_packet(link).unwrap(); // TODO: handle Result
                payloads.into()
            })
        })
    }
}

/// Process a Signed packet message
#[no_mangle]
pub extern "C" fn auth_receive_signed_packet(user: *mut Author, link: *const Address) -> PacketPayloads {
    unsafe {
        user.as_mut().map_or(PacketPayloads::default(), |user| {
            link.as_ref().map_or(PacketPayloads::default(), |link| {
                let signed_payloads = user.receive_signed_packet(link).unwrap(); // TODO: handle Result
                signed_payloads.into()
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn author_receive_sequence(user: *mut Author, link: *const Address) -> *const Address {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            link.as_ref().map_or(null(), |link| {
                let seq_link = user.receive_sequence(link).unwrap(); // TODO: handle Result
                Box::into_raw(Box::new(seq_link))
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn auth_send_signed_packet(
    user: *mut Author,
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

#[no_mangle]
pub extern "C" fn auth_gen_next_msg_ids(user: *mut Author) -> *const NextMsgIds {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            let next_msg_ids = user.gen_next_msg_ids(user.is_multi_branching());
            Box::into_raw(Box::new(next_msg_ids))
        })
    }
}

#[no_mangle]
pub extern "C" fn auth_receive_msg(user: *mut Author, link: *const Address) -> *const UnwrappedMessage {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            link.as_ref().map_or(null(), |link| {
                let u = user.receive_msg(link).unwrap(); // TODO: handle Result
                Box::into_raw(Box::new(u))
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn auth_fetch_next_msgs(user: *mut Author) -> *const UnwrappedMessages {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            let m = user.fetch_next_msgs();
            Box::into_raw(Box::new(m))
        })
    }
}

#[no_mangle]
pub extern "C" fn auth_sync_state(user: *mut Author) -> *const UnwrappedMessages {
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
pub extern "C" fn auth_fetch_state(user: *mut Author) -> *const UserState {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            user.fetch_state().map_or(null(), |state| {
                Box::into_raw(Box::new(state))
            })
        })
    }
}
