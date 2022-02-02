use iota_streams::{
    app::cty::uint8_t,
    app_channels::api::tangle::{
        Address,
        ChannelType,
        Message,
    },
};

#[cfg(not(feature = "client"))]
use iota_streams::{
    app_channels::api::tangle::BucketTransport,
    core::prelude::{Rc, RefCell}
};

#[cfg(any(feature = "client", feature = "external-client"))]
use iota_streams::app::{
    cstr_core::CStr,
    cty::c_char,
    transport::{
        Transport,
        tangle::client::Client
    },
};

use crate::{safe_into_mut_ptr, safe_drop_mut_ptr, run_async, Err, safe_into_ptr};


#[cfg(feature = "client")]
pub type TransportWrap = iota_streams::app::transport::tangle::client::Client;

#[cfg(not(feature = "client"))]
pub type TransportWrap = Rc<RefCell<BucketTransport>>;

#[cfg(feature = "external-client")]
pub type ClientWrap = iota_streams::app::transport::tangle::client::Client;

pub fn get_channel_type(channel_type: uint8_t) -> ChannelType {
    match channel_type {
        0 => ChannelType::SingleBranch,
        1 => ChannelType::MultiBranch,
        2 => ChannelType::SingleDepth,
        _ => ChannelType::SingleBranch,
    }
}

#[no_mangle]
pub extern "C" fn transport_new() -> *mut TransportWrap {
    safe_into_mut_ptr(TransportWrap::default())
}

#[no_mangle]
pub extern "C" fn transport_drop(tsp: *mut TransportWrap) {
    safe_drop_mut_ptr(tsp)
}

#[cfg(feature = "external-client")]
#[no_mangle]
pub unsafe extern "C" fn transport_send_raw(tsp: *mut ClientWrap, msg: *const Message) -> Err {
    tsp.as_mut().map_or(Err::NullArgument, |tsp| {
        iota_streams::core::println!("Got the transport");
        msg.as_ref().map_or(Err::NullArgument, |msg| {
            iota_streams::core::println!("Got the Message");
            run_async(tsp.send_message(msg)).map_or(Err::OperationFailed, |_| Err::Ok)
        })
    })
}

#[cfg(feature = "external-client")]
#[no_mangle]
pub unsafe extern "C" fn transport_receive_raw(
    msg: *mut *const Message,
    tsp: *mut TransportWrap,
    link: *const Address
) -> Err {
    tsp.as_mut().map_or(Err::NullArgument, |tsp| {
        link.as_ref().map_or(Err::NullArgument, |link| {
            msg.as_mut().map_or(Err::NullArgument, |binary_msg| {
                run_async(tsp.recv_message(link)).map_or(Err::OperationFailed, |msg| {
                    *binary_msg = safe_into_ptr(msg);
                    Err::Ok
                })
            })
        })
    })

}

#[cfg(feature = "client")]
#[no_mangle]
pub unsafe extern "C" fn transport_client_new_from_url(c_url: *const c_char) -> *mut TransportWrap {
    let url = CStr::from_ptr(c_url).to_str().unwrap();
    safe_into_mut_ptr(Client::new_from_url(url))
}

#[cfg(feature = "external-client")]
#[no_mangle]
pub unsafe extern "C" fn client_new_from_url(c_url: *const c_char) -> *mut ClientWrap {
    let url = CStr::from_ptr(c_url).to_str().unwrap();
    iota_streams::core::println!("Making client from {}", url);
    safe_into_mut_ptr(ClientWrap::new_from_url(url))
}

#[cfg(feature = "client")]
mod client_details {
    use super::*;
    use iota_streams::app::transport::{
        tangle::client::{
            iota_client::{
                bee_rest_api::types::{
                    dtos::LedgerInclusionStateDto,
                    responses::MessageMetadataResponse,
                },
                MilestoneResponse,
            },
            Details as ApiDetails,
        },
        TransportDetails as _,
    };

    #[repr(C)]
    pub struct TransportDetails {
        metadata: MessageMetadata,
        milestone: Milestone,
    }

    impl From<ApiDetails> for TransportDetails {
        fn from(d: ApiDetails) -> Self {
            Self {
                metadata: d.metadata.into(),
                milestone: d.milestone.map_or(Milestone::default(), |m| m.into()),
            }
        }
    }

    #[repr(C)]
    pub enum LedgerInclusionState {
        Conflicting,
        Included,
        NoTransaction,
    }

    impl From<LedgerInclusionStateDto> for LedgerInclusionState {
        fn from(e: LedgerInclusionStateDto) -> Self {
            match e {
                LedgerInclusionStateDto::Conflicting => Self::Conflicting,
                LedgerInclusionStateDto::Included => Self::Included,
                LedgerInclusionStateDto::NoTransaction => Self::NoTransaction,
            }
        }
    }

    #[repr(C)]
    pub struct MessageMetadata {
        pub message_id: [u8; 129],
        pub parent_message_ids: [[u8; 129]; 2],
        pub is_solid: bool,
        pub referenced_by_milestone_index: u32,
        pub milestone_index: u32,
        pub ledger_inclusion_state: LedgerInclusionState,
        pub conflict_reason: u8,
        pub should_promote: bool,
        pub should_reattach: bool,
        pub field_flags: u32,
    }

    impl Default for MessageMetadata {
        fn default() -> Self {
            unsafe { core::mem::MaybeUninit::zeroed().assume_init() }
        }
    }

    impl From<MessageMetadataResponse> for MessageMetadata {
        fn from(m: MessageMetadataResponse) -> Self {
            let mut r = MessageMetadata::default();
            let field_flags = 0_u32
                | {
                let s = core::cmp::min(r.message_id.len() - 1, m.message_id.as_bytes().len());
                r.message_id[..s].copy_from_slice(&m.message_id.as_bytes()[..s]);
                1_u32 << 0
            }
                | {
                if 0 < m.parent_message_ids.len() {
                    let s = core::cmp::min(
                        r.parent_message_ids[0].len() - 1,
                        m.parent_message_ids[0].as_bytes().len(),
                    );
                    r.parent_message_ids[0][..s].copy_from_slice(&m.parent_message_ids[0].as_bytes()[..s]);
                }
                if 1 < m.parent_message_ids.len() {
                    let s = core::cmp::min(
                        r.parent_message_ids[1].len() - 1,
                        m.parent_message_ids[1].as_bytes().len(),
                    );
                    r.parent_message_ids[1][..s].copy_from_slice(&m.parent_message_ids[1].as_bytes()[..s]);
                }
                // TODO: support more than 2 parents
                // assert!(!(2 < m.parent_message_ids.len()));
                1_u32 << 1
            }
                | {
                r.is_solid = m.is_solid;
                1_u32 << 2
            }
                | m.referenced_by_milestone_index.map_or(0_u32, |v| {
                r.referenced_by_milestone_index = v;
                1_u32 << 3
            })
                | m.milestone_index.map_or(0_u32, |v| {
                r.milestone_index = v;
                1_u32 << 4
            })
                | m.ledger_inclusion_state.map_or(0_u32, |v| {
                r.ledger_inclusion_state = v.into();
                1_u32 << 5
            })
                | m.conflict_reason.map_or(0_u32, |v| {
                r.conflict_reason = v;
                1_u32 << 6
            })
                | m.should_promote.map_or(0_u32, |v| {
                r.should_promote = v;
                1_u32 << 7
            })
                | m.should_reattach.map_or(0_u32, |v| {
                r.should_reattach = v;
                1_u32 << 8
            });
            r.field_flags = field_flags;
            r
        }
    }

    #[repr(C)]
    pub struct Milestone {
        pub milestone_index: u32,
        pub message_id: [u8; 129],
        pub timestamp: u64,
    }

    impl Default for Milestone {
        fn default() -> Self {
            unsafe { core::mem::MaybeUninit::zeroed().assume_init() }
        }
    }

    impl From<MilestoneResponse> for Milestone {
        fn from(m: MilestoneResponse) -> Self {
            let mut r = Milestone::default();
            r.milestone_index = m.index;
            {
                let s = core::cmp::min(r.message_id.len() - 1, m.message_id.as_ref().len());
                r.message_id[..s].copy_from_slice(&m.message_id.as_ref()[..s]);
            }
            r.timestamp = m.timestamp;
            r
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn transport_get_link_details(
        r: *mut TransportDetails,
        tsp: *mut TransportWrap,
        link: *const Address,
    ) -> Err {
        r.as_mut().map_or(Err::NullArgument, |r| {
            tsp.as_mut().map_or(Err::NullArgument, |tsp| {
                link.as_ref().map_or(Err::NullArgument, |link| {
                    run_async(tsp.get_link_details(link)).map_or(Err::OperationFailed, |d| {
                        *r = d.into();
                        Err::Ok
                    })
                })
            })
        })
    }
}

#[cfg(feature = "client")]
pub use client_details::*;
