use crate::{Address, MessageLinks};
use iota_streams::{
    app::transport::tangle::{
        TangleAddress,
        AppInst as ApplicationInstance,
        MsgId as MessageIdentifier,
    },
};

pub fn get_seq_link(unboxed_link: Box<MessageLinks>, branching: bool) -> TangleAddress {
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


pub fn retrieve_links(response: (TangleAddress, Option<TangleAddress>)) -> *mut MessageLinks {
    let msg_links = if response.1.is_none() {
        MessageLinks {
            msg_link: Address(response.0),
            seq_link: None
        }
    } else {
        MessageLinks {
            msg_link: Address(response.0),
            seq_link: Some(Address(response.1.unwrap()))
        }
    };
    Box::into_raw(Box::new(msg_links))

}

