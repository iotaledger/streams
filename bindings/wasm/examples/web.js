import("../pkg/index.js").then(async (streams) => {
    window.streams = streams;
    
    streams.set_panic_hook();

    console.log("Streams loaded!");

    //old_test();
});

async function old_test(){
    let node = "https://nodes.devnet.iota.org:443";
    let options = new streams.SendTrytesOptions(1, 9, true, 1);
    let seed = "LADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let auth = new streams.Author(node, seed, options, false);

    console.log("channel address: ", auth.channel_address());
    console.log("multi branching: ", auth.is_multi_branching());

    let response = await auth.send_announce();
    let ann_link = response.get_link();
    auth = response.to_auth();
    console.log("announced at: ", ann_link.to_string());

    let options2 = new streams.SendTrytesOptions(1, 9, true, 1);
    let seed2 = "EBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
    let sub = new streams.Subscriber(node, seed2, options2, false);

    let ann_link_copy = ann_link.copy();
    sub = await sub.receive_announcement(ann_link_copy);

    console.log("Subscribing...");
    ann_link_copy = ann_link.copy()
    response = await sub.send_subscribe(ann_link_copy)
    let sub_link = response.get_link();
    sub = response.to_sub()
    console.log("Subscription message at: ", sub_link.to_string());
    auth = await auth.receive_subscribe(sub_link);
    console.log("Subscription processed")

    console.log("Sending Keyload")
    response = await auth.send_keyload_for_everyone(ann_link);
    let keyload_link = response.get_link();
    auth = response.to_auth()
    console.log("Keyload message at: ", keyload_link.to_string())

    console.log("Subscriber Sending tagged packet");
    response = await sub.send_tagged_packet(keyload_link, to_bytes("Public"), to_bytes("Masked"));
    let tag_link = response.get_link();
    sub = response.to_sub();
    console.log("Tag packet at: ", tag_link.to_string());

    //auth.free();
}

function to_bytes(str) {
    var bytes = [];
    var charCode;

    for (var i = 0; i < str.length; ++i){
        charCode = str.charCodeAt(i);
        bytes.push((charCode & 0xFF00) >> 8);
        bytes.push(charCode & 0xFF);
    }

    return bytes
}