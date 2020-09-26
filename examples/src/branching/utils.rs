use iota_streams::{
    app::message::HasLink as _,
    app_channels::{
        api::{
            tangle::{
                Author,
                Subscriber,
                Transport,
            },
        },
    },
};

pub fn s_fetch_next_messages<T: Transport>(subscriber: &mut Subscriber<T>)
where
    T::RecvOptions: Copy,
{
    let mut exists = true;

    while exists {
        let msgs = subscriber.fetch_next_msgs().unwrap();
        exists = false;

        for (_pk, link, _public_payload, _private_payload) in msgs {
            println!("Message exists at {}... ", &link.rel());
            exists = true;
        }

        if !exists {
            println!("No more messages in sequence.");
        }
    }
}

pub fn a_fetch_next_messages<T: Transport>(author: &mut Author<T>)
where
    T::RecvOptions: Copy,
{
    let mut exists = true;

    while exists {
        let msgs = author.fetch_next_msgs().unwrap();
        exists = false;

        for (_pk, link, _public_payload, _private_payload) in msgs {
            println!("Message exists at {}... ", &link.rel());
            exists = true;
        }

        if !exists {
            println!("No more messages in sequence.");
        }
    }

}
