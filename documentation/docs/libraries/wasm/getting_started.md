# Getting Started
Before building anything you'll need to make sure you have `npm` installed on your 
machine.

### Install the library
To install the library, you could run:

```npm i @iota/streams-wasm```


### Starting a Channel 
Once the package has been built, you can pull it into a script file like so: 
```javascript
const streams = require("@iota/streams/node/streams.js");

let node = "https://chrysalis-nodes.iota.org/";

// Options include: (node-url, local pow)
let options = new streams.SendOptions(node, true);

let client = await new streams.ClientBuilder().node(node).build();

let auth = streams.Author.fromClient(streams.StreamsClient.fromClient(client), "Unique Seed Here", streams.ChannelType.SingleBranch);

// Response formatting: {link, sequence link, msg }
let response = await auth.clone().send_announce();

let ann_link = response.link;

console.log("Channel Announcement at: ", ann_link.to_string());
```
