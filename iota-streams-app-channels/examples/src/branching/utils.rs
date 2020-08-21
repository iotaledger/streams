use iota_streams_app_channels::{
    api::tangle::{
        Address,
        Author,
        Subscriber,
        Transport,
    },
    message,
};

use iota_streams_app::{
    message::HasLink
};


#[allow(dead_code)]
pub fn s_fetch_next_messages<T: Transport>(subscriber: &mut Subscriber, transport: &mut T, recv_opt: T::RecvOptions, multi_branching_flag: u8)
    where
        T::RecvOptions: Copy,
{
    let mut next_id: Address;
    let mut seq_num: usize;
    let mut exists = true;

    while exists {
        let ids = subscriber.gen_next_msg_ids(multi_branching_flag == 1_u8);
        exists = false;

        for id in ids.iter() {
            next_id = id.1.clone();
            seq_num = id.2.clone();

            let msg = transport.recv_message_with_options(&next_id, recv_opt).ok();
            if msg.is_none() {
                continue
            }

            let mut unwrapped = msg.unwrap();

            loop {
                let preparsed = unwrapped.parse_header().unwrap();
                print!("Message exists at {}... ", &preparsed.header.link.rel());
                match preparsed.header.content_type {
                    message::signed_packet::TYPE => {
                        let _unwrapped = subscriber.unwrap_signed_packet(preparsed.clone());
                        println!("Found a signed packet");
                        break
                    },
                    message::tagged_packet::TYPE => {
                        let _unwrapped = subscriber.unwrap_tagged_packet(preparsed.clone());
                        println!("Found a tagged packet");
                        break
                    },
                    message::keyload::TYPE => {
                        let _unwrapped = subscriber.unwrap_keyload(preparsed.clone());
                        println!("Found a keyload packet");
                        break
                    },
                    message::sequence::TYPE => {
                        print!("Found sequenced message.\tFetching sequenced message... ");
                        let msgid = subscriber.unwrap_sequence(preparsed.clone()).unwrap();
                        let msg = transport.recv_message_with_options(&msgid, recv_opt).ok();
                        subscriber.store_state(id.0.clone(), preparsed.header.link.clone());
                        unwrapped = msg.unwrap();
                    },
                    _ => {
                        println!("Not a recognised type... {}", preparsed.content_type().as_str());
                        break
                    }
                }
            }

            if !(multi_branching_flag == 1_u8) {
                subscriber.store_state_for_all(next_id.clone(), seq_num);
            }
            exists = true;
        }

        if !exists {
            println!("No more messages in sequence.");
        }
    }
}

#[allow(dead_code)]
pub fn a_fetch_next_messages<T: Transport>(author: &mut Author, transport: &mut T, recv_opt: T::RecvOptions, multi_branching_flag: u8)
    where
        T::RecvOptions: Copy,
{
    let mut next_id: Address;
    let mut seq_num: usize;
    let mut exists = true;

    while exists {
        let ids = author.gen_next_msg_ids(multi_branching_flag == 1_u8);
        exists = false;
        for id in ids.iter() {
            next_id = id.1.clone();
            seq_num = id.2.clone();

            let msg = transport.recv_message_with_options(&next_id, recv_opt).ok();
            if msg.is_none() {
                continue
            }
            let mut unwrapped = msg.unwrap();
            loop {
                let preparsed = unwrapped.parse_header().unwrap();
                print!("Message exists at {}... ", &preparsed.header.link.rel());

                match preparsed.header.content_type {
                    message::tagged_packet::TYPE => {
                        let _unwrapped = author.unwrap_tagged_packet(preparsed.clone());
                        println!("Found a tagged packet");
                        break
                    },
                    message::sequence::TYPE => {
                        let msgid = author.unwrap_sequence(preparsed.clone()).unwrap();
                        print!("Found sequenced message.\tFetching sequenced message... ");
                        let msg = transport.recv_message_with_options(&msgid, recv_opt).ok();
                        author.store_state(id.0.clone(), preparsed.header.link.clone());
                        unwrapped = msg.unwrap();
                    },
                    _ => {
                        // If message is found from self, internal state needs to be updated for next round
                        if id.0.as_bytes().eq(author.get_pk().as_bytes()) {
                            println!("Found previous message sent by self, updating sequence state...");
                        } else {
                            println!("Not a recognised type")
                        }
                        break
                    }
                }
            }

            if !(multi_branching_flag == 1_u8) {
                author.store_state_for_all(next_id.clone(), seq_num);
            }
            exists = true;
        }

        if !exists {
            println!("No more messages in sequence.");
        }
    }
}
