use iota::client as iota_client;
use iota_streams_app::transport::{
    TransportOptions,
    tangle::client::{
        Client, SendTrytesOptions,
    },
};
use iota_streams_app_channels::api::tangle::{
    test::example,
};

fn main() {
    iota_client::Client::add_node("https://nodes.devnet.iota.org:443").unwrap();

    let mut send_opt = SendTrytesOptions::default();
    send_opt.min_weight_magnitude = 14;
    let mut tsp = Client::default();
    tsp.set_send_options(send_opt);

    assert!(dbg!(example(tsp)).is_ok());
}
