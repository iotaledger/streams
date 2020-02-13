use failure::ensure;
use std::str::FromStr;
use iota_mam_core::trits::Trits;
use iota_mam_protobuf3::types::Trytes;
use iota_mam_app::{channel::{api::tangle::{*, author::Author, subscriber::Subscriber}, msg}, Result};

fn example() -> Result<()> {
    let mut author = Author::new("AUTHORSSEED", 3, false);
    let mut subscriber = Subscriber::new("SUBSCRIBERSSEED", false);

    let announcement = author.announce()?;

    {
        let preparsed = announcement.parse_header()?;
        ensure!(preparsed.check_content_type(msg::announce::TYPE));
        subscriber.unwrap_announcement(preparsed)?;
    }

    let keyload = author.share_keyload_for_everyone(announcement.link())?;

    {   let preparsed = keyload.parse_header()?;
        ensure!(preparsed.check_content_type(msg::keyload::TYPE));
        subscriber.unwrap_keyload(preparsed)?;
    }

    let public_payload = Trytes(Trits::from_str("PUBLICPAYLOAD").unwrap());
    let masked_payload = Trytes(Trits::from_str("MASKEDPAYLOAD").unwrap());

    let signed_packet = author.sign_packet(announcement.link(), &public_payload, &masked_payload)?;

    {
        let preparsed = signed_packet.parse_header()?;
        ensure!(preparsed.check_content_type(msg::signed_packet::TYPE));
        let (unwrapped_public, unwrapped_masked) = subscriber.unwrap_signed_packet(preparsed)?;
        ensure!(public_payload == unwrapped_public);
        ensure!(masked_payload == unwrapped_masked);
    }

    let tagged_packet = author.tag_packet(announcement.link(), &public_payload, &masked_payload)?;

    {
        let preparsed = tagged_packet.parse_header()?;
        ensure!(preparsed.check_content_type(msg::tagged_packet::TYPE));
        let (unwrapped_public, unwrapped_masked) = subscriber.unwrap_signed_packet(preparsed)?;
        ensure!(public_payload == unwrapped_public);
        ensure!(masked_payload == unwrapped_masked);
    }

    let change_key = author.change_key(announcement.link())?;

    {
        let preparsed = change_key.parse_header()?;
        ensure!(preparsed.check_content_type(msg::change_key::TYPE));
        subscriber.unwrap_change_key(preparsed)?;
    }

    Ok(())
}

fn main() {
    let r = example();
}
