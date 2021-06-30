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
    safe_into_mut_ptr(user)
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
                    safe_into_mut_ptr(auth)
                })
        })
    }
}

/// Import an Author instance from an encrypted binary array
#[no_mangle]
pub extern "C" fn auth_import(
    buffer: Buffer,
    password: *const c_char,
    transport: *mut TransportWrap,
) -> *mut Author {
    unsafe {
        let bytes_vec = Vec::from_raw_parts(
            buffer.ptr as *mut u8,
            buffer.size,
            buffer.cap,
        );
        let password_str = CStr::from_ptr(password).to_str().unwrap();
        let tsp = (*transport).clone();
        Author::import(&bytes_vec, password_str, tsp)
            .map_or(null_mut(), |auth| {
                Box::into_raw(Box::new(auth))
        })
    }
}

#[no_mangle]
pub extern "C" fn auth_export(
    user: *mut Author,
    password: *const c_char
) -> Buffer {
    unsafe {
        let password_str = CStr::from_ptr(password).to_str().unwrap();
        user.as_ref().map_or(Buffer::default(), |user| {
            let bytes = user.export(password_str).unwrap();
            bytes.into()
        })
    }
}

#[no_mangle]
pub extern "C" fn auth_drop(user: *mut Author) {
    safe_drop_mut_ptr(user)
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
            user.send_announce().map_or(null(), |a| safe_into_ptr(a))
        })
    }
}

/// unwrap and add a subscriber to the list of subscribers
#[no_mangle]
pub extern "C" fn auth_receive_subscribe(user: *mut Author, link: *const Address) -> Err {
    unsafe {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, |link| {
                user.receive_subscribe(link).map_or(Err::OperationFailed, |_| Err::Ok)
            })
        })
    }
}

/// Create a new keyload for a list of subscribers.
#[no_mangle]
pub extern "C" fn auth_send_keyload(
    r: *mut MessageLinks,
    user: *mut Author,
    link_to: *const Address,
    psk_ids: *const PskIds,
    ke_pks: *const KePks,
) -> Err {
    unsafe {
        r.as_mut().map_or(Err::NullArgument, |r| {
            user.as_mut().map_or(Err::NullArgument, |user| {
                link_to.as_ref().map_or(Err::NullArgument, |link_to| {
                    psk_ids.as_ref().map_or(Err::NullArgument, |psk_ids| {
                        ke_pks.as_ref().map_or(Err::NullArgument, |ke_pks| {
                            user.send_keyload(link_to, psk_ids, ke_pks)
                                .map_or(Err::OperationFailed, |response| {
                                    *r = response.into();
                                    Err::Ok
                                })
                        })
                    })
                })
            })
        })
    }
}

/// Create keyload for all subscribed subscribers.
#[no_mangle]
pub extern "C" fn auth_send_keyload_for_everyone(r: *mut MessageLinks, user: *mut Author, link_to: *const Address) -> Err {
    unsafe {
        r.as_mut().map_or(Err::NullArgument, |r| {
            user.as_mut().map_or(Err::NullArgument, |user| {
                link_to.as_ref().map_or(Err::NullArgument, |link_to| {
                    user.send_keyload_for_everyone(link_to)
                        .map_or(Err::OperationFailed, |response| {
                            *r = response.into();
                            Err::Ok
                        })
                })
            })
        })
    }
}

/// Process a Tagged packet message
#[no_mangle]
pub extern "C" fn auth_send_tagged_packet(
    r: *mut MessageLinks,
    user: *mut Author,
    link_to: MessageLinks,
    public_payload_ptr: *const uint8_t,
    public_payload_size: size_t,
    masked_payload_ptr: *const uint8_t,
    masked_payload_size: size_t,
) -> Err {
    unsafe {
        r.as_mut().map_or(Err::NullArgument, |r| {
            user.as_mut().map_or(Err::NullArgument, |user| {
                link_to
                    .into_seq_link(user.is_multi_branching())
                    .map_or(Err::NullArgument, |link_to| {
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
                        let e = user
                            .send_tagged_packet(link_to, &public_payload, &masked_payload)
                            .map_or(Err::OperationFailed, |response| {
                                *r = response.into();
                                Err::Ok
                            });
                        let _ = core::mem::ManuallyDrop::new(public_payload.0);
                        let _ = core::mem::ManuallyDrop::new(masked_payload.0);
                        e
                    })
            })
        })
    }
}

/// Process a Tagged packet message
#[no_mangle]
pub extern "C" fn auth_receive_tagged_packet(r: *mut PacketPayloads, user: *mut Author, link: *const Address) -> Err {
    unsafe {
        r.as_mut().map_or(Err::NullArgument, |r| {
            user.as_mut().map_or(Err::NullArgument, |user| {
                link.as_ref().map_or(Err::NullArgument, |link| {
                    user
                        .receive_tagged_packet(link)
                        .map_or(Err::OperationFailed, |tagged_payloads| {
                            *r = tagged_payloads.into();
                            Err::Ok
                        })
                })
            })
        })
    }
}

/// Process a Signed packet message
#[no_mangle]
pub extern "C" fn auth_send_signed_packet(
    r: *mut MessageLinks,
    user: *mut Author,
    link_to: MessageLinks,
    public_payload_ptr: *const uint8_t,
    public_payload_size: size_t,
    masked_payload_ptr: *const uint8_t,
    masked_payload_size: size_t,
) -> Err {
    unsafe {
        r.as_mut().map_or(Err::NullArgument, |r| {
            user.as_mut().map_or(Err::NullArgument, |user| {
                link_to
                    .into_seq_link(user.is_multi_branching())
                    .map_or(Err::NullArgument, |link_to| {
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
                        let e = user
                            .send_signed_packet(link_to, &public_payload, &masked_payload)
                            .map_or(Err::OperationFailed, |response| {
                                *r = response.into();
                                Err::Ok
                            });
                        let _ = core::mem::ManuallyDrop::new(public_payload.0);
                        let _ = core::mem::ManuallyDrop::new(masked_payload.0);
                        e
                    })
            })
        })
    }
}

/// Process a Signed packet message
#[no_mangle]
pub extern "C" fn auth_receive_signed_packet(r: *mut PacketPayloads, user: *mut Author, link: *const Address) -> Err {
    unsafe {
        r.as_mut().map_or(Err::NullArgument, |r| {
            user.as_mut().map_or(Err::NullArgument, |user| {
                link.as_ref().map_or(Err::NullArgument, |link| {
                    user
                        .receive_signed_packet(link)
                        .map_or(Err::OperationFailed, |signed_payloads| {
                            *r = signed_payloads.into();
                            Err::Ok
                        })
                })
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn auth_receive_sequence(r: *mut *const Address, user: *mut Author, link: *const Address) -> Err {
    unsafe {
        r.as_mut().map_or(Err::NullArgument, |r| {
            user.as_mut().map_or(Err::NullArgument, |user| {
                link.as_ref().map_or(Err::NullArgument, |link| {
                    user.receive_sequence(link).map_or(Err::OperationFailed, |seq_link| {
                        *r = safe_into_ptr(seq_link);
                        Err::Ok
                    })
                })
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn auth_gen_next_msg_ids(user: *mut Author) -> *const NextMsgIds {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            let next_msg_ids = user.gen_next_msg_ids(user.is_multi_branching());
            safe_into_ptr(next_msg_ids)
        })
    }
}

#[no_mangle]
pub extern "C" fn auth_receive_msg(r: *mut *const UnwrappedMessage, user: *mut Author, link: *const Address) -> Err {
    unsafe {
        r.as_mut().map_or(Err::NullArgument, |r| {
            user.as_mut().map_or(Err::NullArgument, |user| {
                link.as_ref().map_or(Err::NullArgument, |link| {
                    user.receive_msg(link).map_or(Err::OperationFailed, |u| {
                        *r = safe_into_ptr(u);
                        Err::Ok
                    })
                })
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn auth_fetch_next_msgs(user: *mut Author) -> *const UnwrappedMessages {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            let m = user.fetch_next_msgs();
            safe_into_ptr(m)
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
            safe_into_ptr(ms)
        })
    }
}

#[no_mangle]
pub extern "C" fn auth_fetch_state(user: *mut Author) -> *const UserState {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            user.fetch_state().map_or(null(), |state| {
                safe_into_ptr(state)
            })
        })
    }
}
