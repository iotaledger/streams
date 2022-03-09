import("../pkg/index.js").then(async (streams) => {
  window.streams = streams;

  console.log(streams);
  window.streams.to_bytes = to_bytes;
  window.streams.from_bytes = from_bytes;

  window.streams.set_panic_hook();

  console.log("Streams loaded!");
});

function to_bytes(str) {
  var bytes = [];
  for (var i = 0; i < str.length; ++i) {
    bytes.push(str.charCodeAt(i));
  }
  return bytes;
}

function from_bytes(bytes) {
  var str = "";
  for (var i = 0; i < bytes.length; ++i) {
    str += String.fromCharCode(bytes[i]);
  }
  return str;
}
