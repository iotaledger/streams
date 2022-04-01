---
description: Getting started with Wasm in IOTA Streams.
image: /img/logo/iota_mark_light.png
keywords:
- api
- wasm
- getting started
- reference
---
# Getting Started

Before building anything, you will need to make sure you have [`npm`](https://www.npmjs.com/) installed on your machine.

## Install the Library

To install a library, run:

```bash
npm i @iota/streams
```


## Start a Channel 

Once the package has been built, you can pull it into a script file: 

```javascript
const streams = require("@iota/streams/node");

let node = "https://chrysalis-nodes.iota.org/";

// Options include: (node-url, local pow)
let options = new streams.SendOptions(node, true);

let author = new streams.Author("Unique Seed Here", options.clone(), streams.ChannelType.MultiBranch );

// Response formatting: {link, sequence link, msg }
let response = await author.clone().send_announce();

let ann_link = response.link;

console.log("Channel Announcement at: ", ann_link.toString());
```
