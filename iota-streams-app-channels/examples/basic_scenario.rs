use iota_streams_app::transport::{
    tangle::client::{
        Client,
        SendOptions,
    },
    TransportOptions,
};
use iota_streams_app_channels::api::tangle::test::example;

#[tokio::main]
async fn main() {
    let send_opt = SendOptions::default();
    let mut tsp = Client::new_from_url("https://nodes.devnet.iota.org:443");
    tsp.set_send_options(send_opt);
    assert!(dbg!(example(tsp).await).is_ok());
}
