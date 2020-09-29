use iota_streams::{
    app::message::HasLink as _,
    app_channels::{
        api::{
            tangle::{
                User,
                user::UserImp,
                Transport,
            },
        },
    },
};

pub fn s_fetch_next_messages<T: Transport, U: UserImp>(subscriber: &mut User<T, U>)
where
    T::RecvOptions: Copy + Default,
    T::SendOptions: Copy + Default,
{
    let mut exists = true;

    while exists {
        let msgs = subscriber.fetch_next_msgs();
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

pub fn a_fetch_next_messages<T: Transport, U: UserImp>(author: &mut User<T, U>)
where
    T::RecvOptions: Copy + Default,
    T::SendOptions: Copy + Default,
{
    let mut exists = true;

    while exists {
        let msgs = author.fetch_next_msgs();
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
