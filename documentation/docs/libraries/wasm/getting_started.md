# Getting Started
Before building anything you'll need to make sure you have `npm` installed on your 
machine.

### Install the library
To install the library, you could run:

```npm i @iota/streams```


### Starting a Channel 
Once the package has been built, you can pull it into a script file like so: 
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
