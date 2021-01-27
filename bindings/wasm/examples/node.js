const streams = require('../wasm-node/iota_streams_wasm')
console.log(streams)

const greet = streams.Greet()

console.log("greet: ", greet)