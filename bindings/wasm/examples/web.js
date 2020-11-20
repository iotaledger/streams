import("../pkg/index.js").then((streams) => {

    let seed = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    let options = new streams.SendTrytesOptionsW(1, 14, true, 1);
    let auth = new streams.AuthorW("https://nodes.devnet.iota.org:443", seed, options, false);
    console.log("channel address: ", auth.channel_address());
    console.log("multi branching: ", auth.is_multi_branching());

    auth.free();
});