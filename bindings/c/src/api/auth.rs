use super::*;

pub type Author = iota_streams::app_channels::api::tangle::Author<TransportWrap>;

/// Generate a new Author Instance
#[no_mangle]
pub unsafe extern "C" fn auth_new(
    c_author: *mut *mut Author,
    c_seed: *const c_char,
    channel_type: uint8_t,
    transport: *mut TransportWrap,
) -> Err {
    if c_seed == null() {
        return Err::NullArgument;
    }
    let channel_impl = get_channel_type(channel_type);

    CStr::from_ptr(c_seed).to_str().map_or(Err::BadArgument, |seed| {
        transport.as_ref().map_or(Err::NullArgument, |tsp| {
            c_author.as_mut().map_or(Err::NullArgument, |author| {
                let user = Author::new(seed, channel_impl, tsp.clone());
                *author = safe_into_mut_ptr(user);
                Err::Ok
            })
        })
    })
}

#[cfg(feature = "use-did")]
#[no_mangle]
pub unsafe extern "C" fn auth_new_from_did(
    c_author: *mut *mut Author,
    c_seed: *const c_char,
    channel_type: uint8_t,
    transport: *mut TransportWrap,
    info: *const DIDInfo,
    did_keypair: *const DIDKeypair,
) -> Err {
    if c_seed == null() {
        return Err::NullArgument;
    }
    let channel_impl = get_channel_type(channel_type);

    CStr::from_ptr(c_seed).to_str().map_or(Err::BadArgument, |seed| {
        transport.as_ref().map_or(Err::NullArgument, |tsp| {
            info.as_ref().map_or(Err::NullArgument, |did_info| {
                did_keypair.as_ref().map_or(Err::NullArgument, |keypair| {
                    c_author.as_mut().map_or(Err::NullArgument, |author| {
                        ApiDIDInfo::try_from(did_info).map_or(Err::BadArgument, |api_info| {
                            run_async(Author::new_with_did(
                                seed,
                                channel_impl,
                                tsp.clone(),
                                api_info,
                                &keypair.into(),
                            )).map_or(Err::OperationFailed, |user| {
                                *author = safe_into_mut_ptr(user.0);
                                Err::Ok
                            })
                        })
                    })
                })
            })
        })
    })
}

/// Recover an existing channel from seed and existing announcement message
#[no_mangle]
pub unsafe extern "C" fn auth_recover(
    c_author: *mut *mut Author,
    c_seed: *const c_char,
    c_ann_address: *const Address,
    channel_type: uint8_t,
    transport: *mut TransportWrap,
) -> Err {
    if c_seed == null() {
        return Err::NullArgument;
    }
    let channel_impl = get_channel_type(channel_type);
    CStr::from_ptr(c_seed).to_str().map_or(Err::BadArgument, |seed| {
        c_ann_address.as_ref().map_or(Err::NullArgument, |addr| {
            transport.as_ref().map_or(Err::NullArgument, |tsp| {
                c_author.as_mut().map_or(Err::NullArgument, |author| {
                    run_async(Author::recover(seed, addr, channel_impl, tsp.clone())).map_or(Err::OperationFailed, |user| {
                        *author = safe_into_mut_ptr(user);
                        Err::Ok
                    })
                })
            })
        })
    })
}

#[cfg(feature = "use-did")]
#[no_mangle]
pub unsafe extern "C" fn auth_recover_with_did(
    c_author: *mut *mut Author,
    c_seed: *const c_char,
    c_ann_address: *const Address,
    channel_type: uint8_t,
    transport: *mut TransportWrap,
    info: *const DIDInfo,
) -> Err {
    if c_seed == null() {
        return Err::NullArgument;
    }
    let channel_impl = get_channel_type(channel_type);

    CStr::from_ptr(c_seed).to_str().map_or(Err::BadArgument, |seed| {
        transport.as_ref().map_or(Err::NullArgument, |tsp| {
            info.as_ref().map_or(Err::NullArgument, |did_info| {
                c_ann_address.as_ref().map_or(Err::NullArgument, |ann_address| {
                    c_author.as_mut().map_or(Err::NullArgument, |author| {
                        ApiDIDInfo::try_from(did_info).map_or(Err::BadArgument, |api_info| {
                            run_async(Author::recover_with_did(
                                seed,
                                channel_impl,
                                ann_address,
                                tsp.clone(),
                                api_info,
                            )).map_or(Err::OperationFailed, |user| {
                                *author = safe_into_mut_ptr(user);
                                Err::Ok
                            })
                        })
                    })
                })
            })
        })
    })
}

/// Import an Author instance from an encrypted binary array
#[no_mangle]
pub unsafe extern "C" fn auth_import(
    c_author: *mut *mut Author,
    buffer: Buffer,
    c_password: *const c_char,
    transport: *mut TransportWrap,
) -> Err {
    if c_password == null() {
        return Err::NullArgument;
    }

    CStr::from_ptr(c_password).to_str().map_or(Err::BadArgument, |password| {
        transport.as_ref().map_or(Err::NullArgument, |tsp| {
            c_author.as_mut().map_or(Err::NullArgument, |author| {
                let bytes_vec: Vec<_> = buffer.into();
                run_async(Author::import(&bytes_vec, password, tsp.clone())).map_or(Err::OperationFailed, |user| {
                    *author = safe_into_mut_ptr(user);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_export(buf: *mut Buffer, c_author: *mut Author, c_password: *const c_char) -> Err {
    if c_password == null() {
        return Err::NullArgument;
    }

    CStr::from_ptr(c_password).to_str().map_or(Err::BadArgument, |password| {
        c_author.as_ref().map_or(Err::NullArgument, |user| {
            buf.as_mut().map_or(Err::NullArgument, |buf| {
                run_async(user.export(password)).map_or(Err::OperationFailed, |bytes| {
                    *buf = bytes.into();
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub extern "C" fn auth_drop(user: *mut Author) {
    safe_drop_mut_ptr(user)
}

/// Channel app instance.
#[no_mangle]
pub unsafe extern "C" fn auth_channel_address(addr: *mut *const ChannelAddress, user: *const Author) -> Err {
    user.as_ref().map_or(Err::NullArgument, |user| {
        addr.as_mut().map_or(Err::NullArgument, |addr| {
            user.channel_address().map_or(Err::OperationFailed, |channel_address| {
                *addr = channel_address as *const ChannelAddress;
                Err::Ok
            })
        })
    })
}

/// Channel announcement link.
#[no_mangle]
pub unsafe extern "C" fn auth_announcement_link(addr: *mut *const Address, user: *const Author) -> Err {
    user.as_ref().map_or(Err::NullArgument, |user| {
        addr.as_mut().map_or(Err::NullArgument, |addr| {
            user.announcement_link().map_or(Err::OperationFailed, |ann_link| {
                *addr = safe_into_ptr(ann_link);
                Err::Ok
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_is_multi_branching(flag: *mut uint8_t, user: *const Author) -> Err {
    user.as_ref().map_or(Err::NullArgument, |user| {
        flag.as_mut().map_or(Err::NullArgument, |flag| {
            *flag = if user.is_multi_branching() { 1 } else { 0 };
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_get_public_key(pk: *mut *const PublicKey, user: *const Author) -> Err {
    user.as_ref().map_or(Err::NullArgument, |user| {
        pk.as_mut().map_or(Err::NullArgument, |pk| {
            *pk = user.get_public_key() as *const PublicKey;
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_get_id(id: *mut *const Identifier, user: *const Author) -> Err {
    user.as_ref().map_or(Err::NullArgument, |user| {
        id.as_mut().map_or(Err::NullArgument, |id| {
            *id = user.get_id() as *const Identifier;
            Err::Ok
        })
    })
}


/// Announce creation of a new Channel.
#[no_mangle]
pub unsafe extern "C" fn auth_send_announce(addr: *mut *const Address, user: *mut Author) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        addr.as_mut().map_or(Err::NullArgument, |addr| {
            run_async(user.send_announce()).map_or(Err::OperationFailed, |a| {
                *addr = safe_into_ptr(a);
                Err::Ok
            })
        })
    })
}

/// unwrap and add a subscriber to the list of subscribers
#[no_mangle]
pub unsafe extern "C" fn auth_receive_subscribe(user: *mut Author, link: *const Address) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        link.as_ref().map_or(Err::NullArgument, |link| {
            run_async(user.receive_subscribe(link)).map_or(Err::OperationFailed, |_| Err::Ok)
        })
    })
}

/// unwrap and remove a subscriber from the list of subscribers
#[no_mangle]
pub unsafe extern "C" fn auth_receive_unsubscribe(user: *mut Author, link: *const Address) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        link.as_ref().map_or(Err::NullArgument, |link| {
            run_async(user.receive_unsubscribe(link)).map_or(Err::OperationFailed, |_| Err::Ok)
        })
    })
}

/// Create a new keyload for a list of subscribers.
#[no_mangle]
pub unsafe extern "C" fn auth_send_keyload(
    r: *mut MessageLinks,
    user: *mut Author,
    link_to: *const Address,
    psk_ids: *const PskIds,
    ke_pks: *const KePks,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link_to.as_ref().map_or(Err::NullArgument, |link_to| {
                psk_ids.as_ref().map_or(Err::NullArgument, |psk_ids| {
                    ke_pks.as_ref().map_or(Err::NullArgument, |ke_pks| {
                        let pks = ke_pks.into_iter().copied().map(Into::<Identifier>::into);
                        let psks = psk_ids.into_iter().copied().map(Into::<Identifier>::into);
                        let identifiers: Vec<Identifier> = pks.chain(psks).collect();
                        run_async(user.send_keyload(link_to, &identifiers))
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

/// Create keyload for all subscribed subscribers.
#[no_mangle]
pub unsafe extern "C" fn auth_send_keyload_for_everyone(
    r: *mut MessageLinks,
    user: *mut Author,
    link_to: *const Address,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link_to.as_ref().map_or(Err::NullArgument, |link_to| {
                run_async(user.send_keyload_for_everyone(link_to))
                    .map_or(Err::OperationFailed, |response| {
                        *r = response.into();
                        Err::Ok
                    })
            })
        })
    })
}

/// Process a Tagged packet message
#[no_mangle]
pub unsafe extern "C" fn auth_send_tagged_packet(
    r: *mut MessageLinks,
    user: *mut Author,
    link_to: MessageLinks,
    public_payload_ptr: *const uint8_t,
    public_payload_size: size_t,
    masked_payload_ptr: *const uint8_t,
    masked_payload_size: size_t,
) -> Err {
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
                    let e = run_async(user
                        .send_tagged_packet(link_to, &public_payload, &masked_payload))
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

/// Process a Tagged packet message
#[no_mangle]
pub unsafe extern "C" fn auth_receive_tagged_packet(
    r: *mut PacketPayloads,
    user: *mut Author,
    link: *const Address,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, |link| {
                run_async(user.receive_tagged_packet(link))
                    .map_or(Err::OperationFailed, |tagged_payloads| {
                        *r = tagged_payloads.into();
                        Err::Ok
                    })
            })
        })
    })
}

/// Process a Signed packet message
#[no_mangle]
pub unsafe extern "C" fn auth_send_signed_packet(
    r: *mut MessageLinks,
    user: *mut Author,
    link_to: MessageLinks,
    public_payload_ptr: *const uint8_t,
    public_payload_size: size_t,
    masked_payload_ptr: *const uint8_t,
    masked_payload_size: size_t,
) -> Err {
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
                    let e = run_async(user
                        .send_signed_packet(link_to, &public_payload, &masked_payload))
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

/// Process a Signed packet message
#[no_mangle]
pub unsafe extern "C" fn auth_receive_signed_packet(
    r: *mut PacketPayloads,
    user: *mut Author,
    link: *const Address,
) -> Err {
     r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, move |link|{
                run_async(user.receive_signed_packet(link)).map_or(Err::OperationFailed, |signed_payloads| {
                        *r = signed_payloads.into();
                        Err::Ok
                    })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_receive_sequence(r: *mut *const Address, user: *mut Author, link: *const Address) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, |link| {
                run_async(user.receive_sequence(link)).map_or(Err::OperationFailed, |seq_link| {
                    *r = safe_into_ptr(seq_link);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_gen_next_msg_ids(ids: *mut *const NextMsgIds, user: *mut Author) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        ids.as_mut().map_or(Err::NullArgument, |ids| {
            let next_msg_ids = user.gen_next_msg_ids(user.is_multi_branching());
            *ids = safe_into_ptr(next_msg_ids);
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_receive_msg(
    r: *mut *const UnwrappedMessage,
    user: *mut Author,
    link: *const Address,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, |link| {
                run_async(user.receive_msg(link)).map_or(Err::OperationFailed, |u| {
                    *r = safe_into_ptr(u);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_receive_msg_by_sequence_number(
    r: *mut *const UnwrappedMessage,
    user: *mut Author,
    anchor_link: *const Address,
    msg_num: size_t,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            anchor_link.as_ref().map_or(Err::NullArgument, |link| {
                run_async(user.receive_msg_by_sequence_number(link, msg_num as u32)).map_or(Err::OperationFailed, |u| {
                    *r = safe_into_ptr(u);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_fetch_next_msgs(umsgs: *mut *const UnwrappedMessages, user: *mut Author) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        umsgs.as_mut().map_or(Err::NullArgument, |umsgs| {
            let m = run_async(user.fetch_next_msgs());
            *umsgs = safe_into_ptr(m);
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_fetch_prev_msg(m: *mut *const UnwrappedMessage, user: *mut Author, address: *const Address) -> Err {
    m.as_mut().map_or(Err::NullArgument, |m| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            address.as_ref().map_or(Err::NullArgument, |addr| {
                run_async(user.fetch_prev_msg(addr)).map_or(Err::OperationFailed, |msg| {
                    *m = safe_into_ptr(msg);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_fetch_prev_msgs(umsgs: *mut *const UnwrappedMessages, user: *mut Author, address: *const Address, num_msgs: size_t) -> Err {
    umsgs.as_mut().map_or(Err::NullArgument, |umsgs| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            address.as_ref().map_or(Err::NullArgument, |addr| {
                run_async(user.fetch_prev_msgs(addr, num_msgs)).map_or(Err::OperationFailed, |msgs| {
                    *umsgs = safe_into_ptr(msgs);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_sync_state(umsgs: *mut *const UnwrappedMessages, user: *mut Author) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        umsgs.as_mut().map_or(Err::NullArgument, |umsgs| {
            let mut ms = Vec::new();
            loop {
                let m = run_async(user.fetch_next_msgs());
                if m.is_empty() {
                    break;
                }
                ms.extend(m);
            }
            *umsgs = safe_into_ptr(ms);
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_fetch_state(state: *mut *const UserState, user: *mut Author) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        state.as_mut().map_or(Err::NullArgument, |state| {
            user.fetch_state().map_or(Err::OperationFailed, |st| {
                *state = safe_into_ptr(st);
                Err::Ok
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_reset_state(user: *mut Author) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        user.reset_state().map_or(Err::OperationFailed, |_| Err::Ok)
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_store_psk(c_pskid: *mut *const PskId, c_user: *mut Author, c_psk_seed: *const c_char) -> Err {
    if c_psk_seed == null() {
        return Err::NullArgument;
    }

    CStr::from_ptr(c_psk_seed).to_str().map_or(Err::BadArgument, |psk_seed| {
        c_user.as_mut().map_or(Err::NullArgument, |user| {
            c_pskid.as_mut().map_or(Err::NullArgument, |pskid| {
                let psk = psk_from_seed(psk_seed.as_ref());
                let id = pskid_from_psk(&psk);
                user.store_psk(id, psk).map_or(Err::OperationFailed, |_| {
                    *pskid = safe_into_ptr(id);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_remove_psk(c_user: *mut Author, c_pskid: *const PskId) -> Err {
    c_user.as_mut().map_or(Err::NullArgument, |user| {
        c_pskid.as_ref().map_or(Err::NullArgument, |pskid| {
            user.remove_psk(*pskid).map_or(Err::OperationFailed, |_| Err::Ok)
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_store_new_subscriber(c_user: *mut Author, c_pk: *const PublicKey) -> Err {
    c_user.as_mut().map_or(Err::NullArgument, |user| {
        c_pk.as_ref().map_or(Err::NullArgument, |pk| {
            user.store_new_subscriber(*pk).map_or(Err::OperationFailed, |_| Err::Ok)
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_remove_subscriber(c_user: *mut Author, c_pk: *const PublicKey) -> Err {
    c_user.as_mut().map_or(Err::NullArgument, |user| {
        c_pk.as_ref().map_or(Err::NullArgument, |pk| {
            user.remove_subscriber(*pk).map_or(Err::OperationFailed, |_| Err::Ok)
        })
    })
}