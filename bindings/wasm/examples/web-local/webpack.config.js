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
  plugins: [
    new CopyWebPlugin({
      patterns: [
        {
          from: path.resolve(__dirname, "static")
        }
      ]
    }),

    new WasmPackPlugin({
      crateDirectory: path.resolve(__dirname, "../.."),
      outDir: "examples/web/pkg"
    }),
  ],
  experiments: {
    syncWebAssembly: true
  }
};