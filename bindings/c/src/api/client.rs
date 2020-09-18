use crate::{Message, Address};
use iota_streams::app_channels::api::tangle::Transport as Trans;
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


//#[no_mangle]
pub fn send_message<T: Trans>(transport: &mut T, msg: &Message) -> ()
where
    T::SendOptions: Default,
{
        //let message = Box::from_raw(msg).0;
        let sent_message = transport.send_message(&msg.0);
        if sent_message.is_err() {
            println!("Sent message failed: {:?}", sent_message.err().unwrap());
        } else {
            println!("Message sent");
        };

}

pub fn recv_message<T: Trans>(transport: &mut T, link: &Address) -> Option<Message>
where
    T::RecvOptions: Default,
{
    let recv_message = transport.recv_message(&link.0);
    if recv_message.is_err() {
        println!("Receiving message failed: {:?}", recv_message.err().unwrap());
        None
    } else {
        println!("Message received");
        Some(Message(recv_message.unwrap()))
    }
}


/*
fn get_transport<T: Transport>(transport: &mut T) -> T
where
    T::SendOptions: Default,
{
    &mut transport
}*/
