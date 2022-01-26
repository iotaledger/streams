use iota_streams::{
    app::message::HasLink as _,
    app_channels::api::tangle::{
        User,
        Transport,
    },
};

pub async fn fetch_next_messages<T: Transport>(user: &mut User<T>) {
    let mut exists = true;

    while exists {
        let msgs = user.fetch_next_msgs().await;
        exists = false;

        for msg in msgs {
            println!("Message exists at {}... ", &msg.link.rel());
            exists = true;
        }

        if !exists {
            println!("No more messages in sequence.");
        }
    }
}