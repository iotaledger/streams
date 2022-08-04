const path = require("path");
const CopyWebPlugin = require('copy-webpack-plugin');
const WasmPackPlugin = require("@wasm-tool/wasm-pack-plugin");

const dist = path.resolve(__dirname, "dist");

module.exports = {
  mode: "production",
  entry: {
    index: "./web.js"
  },
  output: {
    path: dist,
    filename: "[name].js"
  },
  devServer: {
    static: dist,
  },
  performance: {
    maxAssetSize: 3512000
  },
  plugins: [
    new CopyWebPlugin({
      patterns: [
        {
          from: path.resolve(__dirname, "..", "web-static")
        }
      ]
    }),

    new WasmPackPlugin({
      crateDirectory: path.resolve(__dirname, "..", ".."),
      outDir: path.resolve(__dirname, "..", "..", "web"),
    }),
  ],
  experiments: {
    syncWebAssembly: true
  }
};