let streams = require("wasm-bindgen-test.js");

exports.publicKeysWith = (key) => {
    let publicKeys = new streams.PublicKeys();
    publicKeys.add(key);
    return publicKeys;
}