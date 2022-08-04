import init, * as streams from "@iota/streams/web";


async function load() {
    await init();

    window.streams = streams;
    window.streams.set_panic_hook();

    console.log("Streams loaded!");
    // Use Streams as you please
}

load()