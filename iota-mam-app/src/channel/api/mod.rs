use std::collections::HashMap;
use iota_mam_core::{signature::mss, key_encapsulation::ntru, psk};

use crate::core::{HasLink, LinkGenerator};
use crate::core::transport::tangle::{TangleAddress, DefaultTangleLinkGenerator};

pub trait ChannelLinkGenerator<Link> where
    Link: HasLink,
    Self: LinkGenerator<Link, mss::PublicKey> + LinkGenerator<Link, <Link as HasLink>::Rel>
{}
impl ChannelLinkGenerator<TangleAddress> for DefaultTangleLinkGenerator {}

pub mod author;
pub mod subscriber;

pub use author::Author;
pub use subscriber::Subscriber;

pub type Psks = HashMap<psk::PskId, psk::Psk>;
pub type PskIds = Vec<psk::PskId>;
    
pub(crate) fn filter_psks<'a>(psks: &'a Psks, pskids: &'_ PskIds) -> Vec<(&'a psk::PskId, &'a psk::Psk)> {
    psks
       .iter()
       .filter(|(k,v)| pskids.iter().find(|pskid| **pskid == **k).is_some())
       .collect::<Vec<(&psk::PskId, &psk::Psk)>>()
}

pub type NtruPks = HashMap<ntru::Pkid, ntru::PublicKey>;
pub type NtruPkids = Vec<ntru::Pkid>;

pub(crate) fn filter_ntru_pks<'a>(ntru_pks: &'a NtruPks, ntru_pkids: &'_ NtruPkids) -> Vec<(&'a ntru::Pkid, &'a ntru::PublicKey)> {
    ntru_pks
       .iter()
       .filter(|(k,v)| ntru_pkids.iter().find(|ntru_pkid| **ntru_pkid == **k).is_some())
       .collect::<Vec<(&ntru::Pkid, &ntru::PublicKey)>>()
}


#[cfg(test)]
mod test {
    use super::*;
    use iota_mam_protobuf3::types::*;
    use crate::channel::api;
    use api::{Author, Subscriber};

    #[test]
    fn basic_scenario() {
        //let mut author = Author::gen();
    }

    /*
    use crate::channel::msg::*;
    use crate::core::{AppInst, Err, msg::header, MSGID_SIZE, Message, MsgId, msg_typ_eq, Result, Transport};
    use iota_mam_protobuf3::protobuf3;
    use iota_mam_core::{prng, trits::{Trits}};

    struct FakeTangle {
        msgs: Vec<Message>,
    }
    impl FakeTangle {
        fn new() -> Self {
            FakeTangle {
                msgs: Vec::new(),
            }
        }
    }
    impl Transport for FakeTangle {
        fn send(&mut self, msg: &Message) -> Result<()> {
            self.msgs.push(msg.clone());
            Ok(())
        }
        fn recv(&mut self, appinst: &AppInst, msgid: &MsgId) -> Result<Vec<Message>> {
            Ok( self.msgs
                .iter()
                .filter(|m| m.appinst == *appinst && m.msgid == *msgid)
                .cloned()
                .collect()
            )
        }
    }
    
    fn run_basic_scenario() -> Result<()> {
        let author_mss_d = 3;
        let mut author = Author::gen(prng::dbg_init_str("AUTHORPRNGKEY"), &Trits::from_str("AUTHORNONCE").unwrap(), author_mss_d, true);
        println!("1");

        // The first message in the Channel application instance is Announce.
        let announce_msg = author.announce()?;
        println!("2");

        // Subscriber lives in the same Channel application instance.
        // Appinst is published by the Author via other means (published on a web-site).
        let the_appinst = announce_msg.appinst.clone();
        let mut subscriber = Subscriber::gen(the_appinst, prng::dbg_init_str("SUBSCRIBERPRNGKEY"));
        println!("3");
        subscriber.handle_msg(&announce_msg)?;
        println!("4");

        // Author can publish signed packets...
        let public_payload = protobuf3::Trytes(Trits::from_str("PUBLIC").unwrap());
        let masked_payload = protobuf3::Trytes(Trits::from_str("MASKED").unwrap());
        println!("");
        let signed_packet_1 = author.sign_packet(announce_msg.link(), &public_payload, &masked_payload)?;
        // And any Subscriber (even unsubscribed one) can verify them.
        println!("5");
        let payload = subscriber.handle_msg(&signed_packet_1)?;
        println!("6");

        /*
        let subscribe_msg = subscriber.subscribe();
        author.handle_msg(&subscribe_msg);
         */

        Ok(())
    }

    #[test]
    fn basic_scenario() {
        assert_eq!(Ok(()), run_basic_scenario());
    }
     */
}
