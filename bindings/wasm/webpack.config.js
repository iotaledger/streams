const path = require("path");
const CopyPlugin = require("copy-webpack-plugin");
const WasmPackPlugin = require("@wasm-tool/wasm-pack-plugin");
const NodePolyfillPlugin = require("node-polyfill-webpack-plugin")

const dist = path.resolve(__dirname, "dist");

module.exports = {
  mode: "production",
  entry: {
    index: "./examples/web.js"
  },
  output: {
    path: dist,
    filename: "[name].js"
  },
  resolve: {
    fallback: {
      "path": require.resolve("path-browserify")
    }
  },
  devServer: {
    contentBase: dist,
  },
  experiments: {
    outputModule: false,
    syncWebAssembly: true,
    topLevelAwait: false,
    asyncWebAssembly: false,
  },
  plugins: [
    new CopyPlugin({ 
        patterns:[
        path.resolve(__dirname, "static")
      ]
    }),

    new NodePolyfillPlugin({
			excludeAliases: ["console"]
		}),

    new WasmPackPlugin({
      crateDirectory: __dirname,
    }),
  ],
  // Makes the output less verbose
  stats: 'minimal',
  // Removes the asset size warning
  performance: {
    hints: false,
  },
  experiments: {
    asyncWebAssembly: true
  }
};
