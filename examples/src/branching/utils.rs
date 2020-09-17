use iota_streams::{
    app::message::HasLink as _,
    app_channels::{
        api::tangle::{
            Author,
            Subscriber,
            Transport,
        },
        message,
    },
};

pub fn s_fetch_next_messages<T: Transport>(
    subscriber: &mut Subscriber,
    transport: &mut T,
    recv_opt: T::RecvOptions,
    multi_branching: bool,
) where
    T::RecvOptions: Copy,
{
    let mut exists = true;

    while exists {
        let ids = subscriber.gen_next_msg_ids(multi_branching);
        exists = false;

        for (pk, (next_id, seq_num)) in ids.iter() {
            let msg = transport.recv_message_with_options(&next_id, recv_opt).ok();
            if msg.is_none() {
                continue;
            }

            let mut unwrapped = msg.unwrap();

            loop {
                let preparsed = unwrapped.parse_header().unwrap();
                print!("Message exists at {}... ", &preparsed.header.link.rel());
                match preparsed.header.content_type.0 {
                    message::SIGNED_PACKET => {
                        let _unwrapped = subscriber.unwrap_signed_packet(preparsed.clone());
                        println!("Found a signed packet");
                        break;
                    }
                    message::TAGGED_PACKET => {
                        let _unwrapped = subscriber.unwrap_tagged_packet(preparsed.clone());
                        println!("Found a tagged packet");
                        break;
                    }
                    message::KEYLOAD => {
                        let _unwrapped = subscriber.unwrap_keyload(preparsed.clone());
                        println!("Found a keyload packet");
                        break;
                    }
                    message::SEQUENCE => {
                        print!("Found sequenced message.\tFetching sequenced message... ");
                        let msgid = subscriber.unwrap_sequence(preparsed.clone()).unwrap();
                        let msg = transport.recv_message_with_options(&msgid, recv_opt).ok();
                        subscriber.store_state(pk.clone(), preparsed.header.link.clone());
                        unwrapped = msg.unwrap();
                    }
                    _ => {
                        println!("Not a recognised type... {}", preparsed.content_type());
                        break;
                    }
                }
            }

            if !(multi_branching) {
                subscriber.store_state_for_all(next_id.clone(), *seq_num);
            }
            exists = true;
        }

        if !exists {
            println!("No more messages in sequence.");
        }
    }
}

pub fn a_fetch_next_messages<T: Transport>(
    author: &mut Author,
    transport: &mut T,
    recv_opt: T::RecvOptions,
    multi_branching: bool,
) where
    T::RecvOptions: Copy,
{
    let mut exists = true;

    while exists {
        let ids = author.gen_next_msg_ids(multi_branching);
        exists = false;
        for (pk, (next_id, seq_num)) in ids.iter() {
            let msg = transport.recv_message_with_options(&next_id, recv_opt).ok();
            if msg.is_none() {
                continue;
            }
            let mut unwrapped = msg.unwrap();
            loop {
                let preparsed = unwrapped.parse_header().unwrap();
                print!("Message exists at {}... ", &preparsed.header.link.rel());

                match preparsed.header.content_type.0 {
                    message::TAGGED_PACKET => {
                        let _unwrapped = author.unwrap_tagged_packet(preparsed.clone());
                        println!("Found a tagged packet");
                        break;
                    }
                    message::SEQUENCE => {
                        let msgid = author.unwrap_sequence(preparsed.clone()).unwrap();
                        print!("Found sequenced message.\tFetching sequenced message... ");
                        let msg = transport.recv_message_with_options(&msgid, recv_opt).ok();
                        author.store_state(pk.clone(), preparsed.header.link.clone());
                        unwrapped = msg.unwrap();
                    }
                    _ => {
                        // If message is found from self, internal state needs to be updated for next round
                        if pk == author.get_pk() {
                            println!("Found previous message sent by self, updating sequence state...");
                        } else {
                            println!("Not a recognised type")
                        }
                        break;
                    }
                }
            }

            if !(multi_branching) {
                author.store_state_for_all(next_id.clone(), *seq_num);
            }
            exists = true;
        }

        if !exists {
            println!("No more messages in sequence.");
        }
    }
}
