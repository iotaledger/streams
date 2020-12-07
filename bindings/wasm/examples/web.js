import("../pkg/index.js").then(async (streams) => {

    let options = new streams.SendTrytesOptions(1, 9, true, 1);
    let seed = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let auth = new streams.Author("https://nodes.devnet.iota.org:443", seed, options, false);

    console.log("channel address: ", auth.channel_address());
    console.log("multi branching: ", auth.is_multi_branching());
    let ann_link = await auth.send_announce();
    console.log("announced at: ", ann_link);

    let options2 = new streams.SendTrytesOptions(1, 9, true, 1);
    let seed2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
    let sub = new streams.Subscriber("https://nodes.devnet.iota.org:443", seed2, options2, false);

    //console.log("sub channel address: ", sub.channel_address());
    //await sub.receive_announcement(ann_link);
    //console.log("sub channel address: ", sub.channel_address());

    //auth.free();
});
