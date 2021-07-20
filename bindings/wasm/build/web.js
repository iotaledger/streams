const path = require('path')
const fs = require('fs')

const entryFilePath = path.join(__dirname, '../web/iota_streams_wasm.js')
const entryFile = fs.readFileSync(entryFilePath).toString()

// comment out this code so it works for Webpack
/*
fs.writeFileSync(
  entryFilePath,
  entryFile.replace(
    "input = import.meta.url.replace(",
    "// input = import.meta.url.replace("
  )
)*/