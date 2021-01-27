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
    let mut send_opt = SendTrytesOptions::default();
    send_opt.min_weight_magnitude = 9;
    let mut tsp = Client::default();
    tsp.set_send_options(send_opt);
    tsp.add_node("https://nodes.devnet.iota.org:443").unwrap();

    #[cfg(not(feature = "async"))]
    assert!(dbg!(example(tsp)).is_ok());
    #[cfg(feature = "async")]
    assert!(dbg!(smol::block_on(example(tsp))).is_ok());
}
