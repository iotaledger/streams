# IOTA streams WASM

## Setup for development

```bash
git clone https://github.com/iotaledger/streams
cd streams/bindings/wasm
npm install
```

## Browser example
The web example is a self-containing module to show the minimal requirements.
It is pointing at `web-local` by default (which uses the current streams repo to compile). 
We also provide a `web-npm` example which uses the streams package on the npm registry.

```bash
npm run example:web
```

## NodeJS only example:

```bash
npm run build:nodejs
```

```bash
npm run example:nodejs
```

## Generate docs
```bash
npm run doc:nodejs
```

The generated docs are available in `node/jsdocs/index.html`
