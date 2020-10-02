use crate::{Address, Message, MessageLinks, send_message, recv_message};
use iota::client::Client;
use iota_streams::app::transport::tangle::{
        TangleAddress,
        AppInst as ApplicationInstance,
        MsgId as MessageIdentifier,
};
use iota_streams::app_channels::api::tangle::Message as TangleMessage;

#[no_mangle]
pub extern "C" fn get_transaction(link_to: *mut Address) -> *mut Message {
    unsafe {
        let unboxed_address = Box::from_raw(link_to);

        let tangle_address = Address(
            TangleAddress::new(unboxed_address.0.appinst.clone(), unboxed_address.0.msgid.clone())
        );
        std::mem::forget(unboxed_address);

        let response = recv_message(&mut Client::get(), &tangle_address);

        if response.is_some() {
            let msg = response.unwrap();
            println!("Found message: {}", &msg.0.link);
            Box::into_raw(Box::new(msg))
        } else {
            println!("Error fetching message... Does not appear to exist");
            std::ptr::null_mut()
        }
    }
}


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


pub fn send_and_retrieve_links(response: (TangleMessage, Option<TangleMessage>)) -> *mut MessageLinks {
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

