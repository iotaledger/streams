// auth
// sub

// keyload_link
// last_link

async function updateAuthor() {
  if (!streams) {
    console.log("Not yet loaded...");
    return;
  }
  let form = document.forms.settings;
  let options = new streams.SendTrytesOptions(
    form["depth"].value,
    form["mwm"].value,
    form["local_pow"].value === "true",
    form["threads"].value
  );

  auth = new streams.Author(
    form["url"].value,
    form["seed_a"].value,
    options,
    form["multi_branching"].value === "true"
  );

  setText("announce-address", auth.channel_address());
  setText("announce-multi", auth.is_multi_branching());
  announce();
  start_fetch();
}

async function updateSubscriber() {
  if (!streams) {
    console.log("Not yet loaded...");
    return;
  }
  let form = document.forms.settings;
  let options = new streams.SendTrytesOptions(
    form["depth"].value,
    form["mwm"].value,
    form["local_pow"].value === "true",
    form["threads"].value
  );
  sub = new streams.Subscriber(
    form["url"].value,
    form["seed_b"].value,
    options,
    form["multi_branching"].value === "true"
  );
}

function copy_link() {
  var range = document.createRange();
  range.selectNode(document.getElementById("announce-link"));
  window.getSelection().removeAllRanges(); // clear current selection
  window.getSelection().addRange(range); // to select text

  document.execCommand("copy");
  window.getSelection().removeAllRanges();// to deselect
}

function copy_sub_link() {
  var range = document.createRange();
  range.selectNode(document.getElementById("sub-link-out"));
  window.getSelection().removeAllRanges(); // clear current selection
  window.getSelection().addRange(range); // to select text

  document.execCommand("copy");
  window.getSelection().removeAllRanges();// to deselect
}


async function announce() {
  if (!streams) {
    console.log("Not yet loaded...");
    return;
  }

  let response = await auth.clone().send_announce();
  let ann_link = response.get_link();
  setText("announce-link", ann_link.to_string());
}

async function subscribe(fieldname) {
  let link = document.getElementById(fieldname).value;
  if (link.length !== 105) {
    alert("Subscribe link is not correct (105 characters required)");
    return;
  }
  let annLink = streams.Address.from_string(link);

  await sub.clone().receive_announcement(annLink.copy());

  let response = await sub.clone().send_subscribe(annLink);
  let sub_link = response.get_link();
  setText("sub-link-out", sub_link.to_string());

  console.log("sub link: " + sub_link.to_string());
}

async function receive_subscribe(fieldname){
  let link = document.getElementById(fieldname).value;
  if (link.length !== 105) {
    alert("Subscribe link is not correct (105 characters required)");
    return;
  }
  let sub_link = streams.Address.from_string(link);
  await auth.clone().receive_subscribe(sub_link);
}

async function send_keyload(fieldname) {
  let link = document.getElementById(fieldname).textContent;
  let ann_link = streams.Address.from_string(link);

  response = await auth.clone().send_keyload_for_everyone(ann_link);
  keyload_link = response.get_link();
  setText("latest-msg-link", keyload_link.to_string())

  console.log("keyload link: " + keyload_link.to_string());
}

async function unsubscribe(fieldname) {}

function start_fetch(){
  let amount = document.getElementById("auto_fetch").value;
  let interval = amount * 1000;
  window.setInterval(function(){
    fetch_messages();
  }, interval);
}

function stop_fetch(){
  clearInterval();
}

async function fetch_messages() {
  console.log("fetching...");

  let as_auth = document.getElementById("msg_who_auth").value === false;

  let msgs;
  if (as_auth) {
    msgs = await auth.clone().fetch_next_msgs();
  } else {
    msgs = await sub.clone().fetch_next_msgs();
  }

  let msg_text = document.getElementById("messages").textContent;
  for (var i=0; i < msgs.length; ++i) {
    let msg = msgs[i].get_message();
    msg_text += "Msg found: ";
    msg_text += msgs[i].get_link().to_string();
    msg_text += "\nPublic: ";
    msg_text += streams.from_bytes(msg.get_public_payload());
    msg_text += "\nMasked: ";
    msg_text += streams.from_bytes(msg.get_masked_payload());
    msg_text += "\n\n";
  }

  setText("messages", msg_text);
}

async function send_message(form) {
  let msg = form["message"].value;
  let masked = form["masked"].value === "true";
  let send_as_auth = form["msg_who"].value === "true";

  let public_msg = streams.to_bytes(masked ? "" : msg);
  let masked_msg = streams.to_bytes(masked ? msg : "");

  let last_link = document.getElementById("latest-msg-link").textContent;
  console.log("Lastlink: ", last_link);
  last_link = streams.Address.from_string(last_link);

  if (send_as_auth){
    console.log("Author Sending tagged packet");
    response = await auth.clone().send_tagged_packet(last_link, public_msg, masked_msg);
    last_link = response.get_link();
  } else {
    console.log("Subscriber Sending tagged packet");
    response = await sub.clone().send_tagged_packet(last_link, public_msg, masked_msg);
    last_link = response.get_link();
  }
  setText("latest-msg-link", last_link.to_string())

  console.log("Tag packet at: ", last_link.to_string());
}

function setText(id, text) {
  element1 = document.getElementById(id);
  element1.innerHTML = text;
}
