use crate::{Message};
use iota_streams::app_channels::api::tangle::Transport as Trans;
use std::ops::Deref;
/*
#[no_mangle]
pub extern "C" fn get_transport<T: Trans>(client: T) -> *mut Transport<T>
where
    T::SendOptions: Default,
{
    unsafe {
        Box::into_raw(Box::new(Transport(client)))
    }
}*/


#[no_mangle]
pub extern "C" fn send_message<T: Trans>(transport: &mut T, msg: &Message) -> ()
where
    T::SendOptions: Default,
{
    unsafe {
        //let message = Box::from_raw(msg).0;
        let sent_message = transport.send_message(&msg.0);
        if sent_message.is_err() {
            println!("Sent message failed on unwrap: {:?}", sent_message.err().unwrap());
        } else {
            println!("Message sent");
        };
    }
}



/*
fn get_transport<T: Transport>(transport: &mut T) -> T
where
    T::SendOptions: Default,
{
    &mut transport
}*/
