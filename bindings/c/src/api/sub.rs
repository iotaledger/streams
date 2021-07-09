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
    safe_into_mut_ptr(subscriber)
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
                    safe_into_mut_ptr(sub)
                })
        })
    }
}

/// Import an Author instance from an encrypted binary array
#[no_mangle]
pub extern "C" fn sub_import(
    buffer: Buffer,
    password: *const c_char,
    transport: *mut TransportWrap,
) -> *mut Subscriber {
    unsafe {
        let bytes_vec = Vec::from_raw_parts(
            buffer.ptr as *mut u8,
            buffer.size,
            buffer.cap,
        );
        let password_str = CStr::from_ptr(password).to_str().unwrap();
        let tsp = (*transport).clone();
        Subscriber::import(&bytes_vec, password_str, tsp)
            .map_or(null_mut(), |sub| {
                Box::into_raw(Box::new(sub))
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_export(
    user: *mut Subscriber,
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
pub extern "C" fn sub_drop(user: *mut Subscriber) {
    safe_drop_mut_ptr(user)
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
pub extern "C" fn sub_receive_announce(user: *mut Subscriber, link: *const Address) -> Err {
    unsafe {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, |link| {
                user.receive_announcement(link).map_or(Err::OperationFailed, |_| Err::Ok)
            })
        })
    }
}

/// Subscribe to a Channel app instance.
#[no_mangle]
pub extern "C" fn sub_send_subscribe(r: *mut *const Address, user: *mut Subscriber, announcement_link: *const Address) -> Err {
    unsafe {
        r.as_mut().map_or(Err::NullArgument, |r| {
            user.as_mut().map_or(Err::NullArgument, |user| {
                announcement_link.as_ref().map_or(Err::NullArgument, |announcement_link| -> Err {
                    user
                        .send_subscribe(announcement_link)
                        .map_or(Err::OperationFailed, |link| -> Err {
                            *r = safe_into_ptr(link);
                            Err::Ok
                        })
                })
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_send_tagged_packet(
    r: *mut MessageLinks,
    user: *mut Subscriber,
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

#[no_mangle]
pub extern "C" fn sub_send_signed_packet(
    r: *mut MessageLinks,
    user: *mut Subscriber,
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


/// Process a keyload message
#[no_mangle]
pub extern "C" fn sub_receive_keyload(user: *mut Subscriber, link: *const Address) -> Err {
    unsafe {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, |link| {
                user.receive_keyload(link)
                    .map_or(Err::OperationFailed, |_| Err::Ok)
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_receive_sequence(r: *mut *const Address, user: *mut Subscriber, link: *const Address) -> Err {
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

/// Process a Tagged packet message
#[no_mangle]
pub extern "C" fn sub_receive_tagged_packet(r: *mut PacketPayloads, user: *mut Subscriber, link: *const Address) -> Err {
    unsafe {
        r.as_mut().map_or(Err::NullArgument, |r| {
            user.as_mut().map_or(Err::NullArgument, |user| {
                link.as_ref().map_or(Err::NullArgument, |link| {
                    user.receive_tagged_packet(link)
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
pub extern "C" fn sub_receive_signed_packet(r: *mut PacketPayloads, user: *mut Subscriber, link: *const Address) -> Err {
    unsafe {
        r.as_mut().map_or(Err::NullArgument, |r| {
            user.as_mut().map_or(Err::NullArgument, |user| {
                link.as_ref().map_or(Err::NullArgument, |link| {
                    user.receive_signed_packet(link)
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
pub extern "C" fn sub_gen_next_msg_ids(user: *mut Subscriber) -> *const NextMsgIds {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            let next_msg_ids = user.gen_next_msg_ids(user.is_multi_branching());
            safe_into_ptr(next_msg_ids)
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_receive_keyload_from_ids(r: *mut MessageLinks, user: *mut Subscriber, next_msg_ids: *const NextMsgIds) -> Err {
    unsafe {
        r.as_mut().map_or(Err::NullArgument, |r| {
            user.as_mut().map_or(Err::NullArgument, |user| {
                next_msg_ids.as_ref().map_or(Err::NullArgument, |ids| {
                    for (_pk, cursor) in ids {
                        let keyload_link = user.receive_sequence(&cursor.link);
                        if keyload_link.is_ok() {
                            let keyload_link = keyload_link.unwrap();
                            match user.receive_keyload(&keyload_link) {
                                Ok(true) => {
                                    *r = (cursor.link.clone(), Some(keyload_link)).into();
                                    return Err::Ok;
                                },
                                Ok(false) => {},
                                Err(_) => return Err::OperationFailed,
                            }
                        }
                    }
                    Err::OperationFailed
                })
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_receive_msg(r: *mut *const UnwrappedMessage, user: *mut Subscriber, link: *const Address) -> Err {
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
pub extern "C" fn sub_fetch_next_msgs(r: *mut *const UnwrappedMessages, user: *mut Subscriber) -> Err {
    unsafe {
        r.as_mut().map_or(Err::NullArgument, |r| {
            user.as_mut().map_or(Err::NullArgument, |user| {
                let m = user.fetch_next_msgs();
                *r = safe_into_ptr(m);
                Err::Ok
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_sync_state(r: *mut *const UnwrappedMessages, user: *mut Subscriber) -> Err {
    unsafe {
        r.as_mut().map_or(Err::NullArgument, |r| {
            user.as_mut().map_or(Err::NullArgument, |user| {
                let mut ms = Vec::new();
                loop {
                    let m = user.fetch_next_msgs();
                    if m.is_empty() {
                        break;
                    }
                    ms.extend(m);
                }
                *r = safe_into_ptr(ms);
                Err::Ok
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_fetch_state(user: *mut Subscriber) -> *const UserState {
    unsafe {
        user.as_mut().map_or(null(), |user| {
            user.fetch_state().map_or(null(), |state| {
                safe_into_ptr(state)
            })
        })
    }
}

#[no_mangle]
pub extern "C" fn sub_store_psk(user: *mut Subscriber, psk_seed_str: *const c_char) -> *const PskId {
    unsafe {
        let psk_seed = CStr::from_ptr(psk_seed_str).to_str().unwrap();
        user.as_mut().map_or(null(), |user| {
            let psk = psk_from_seed(psk_seed.as_ref());
            let pskid = pskid_from_psk(&psk);
            user.store_psk(pskid.clone(), psk);
            safe_into_ptr(pskid)
        })
    }
}

