var auth;
var subs;
var node_url;
var send_options;

var ann_link;
var last_link;

var fetching = false;
var busy = false;
var page_id = "settings-container";

var sender_id;
var count = 0;

var router = {
  settings: "settings-container",
  announcement: "announcement-information",
  users: "add-users",
  chat: "chat-menu",
}

async function updateAuthor() {
  if (!streams) {
    console.log("Not yet loaded...");
    return;
  }

  console.log(streams);
  auth = null;
  let form = document.forms.settings;
  send_options = new streams.SendOptions(
    form["depth"].value,
    true,
    1,
  );

  node_url = form["url"].value;
  auth = new streams.Author(
    node_url,
    form["seed_a"].value,
    send_options.clone(),
    false,
  );

  announce();
}


async function announce() {
  if (!streams) {
    console.log("Not yet loaded...");
    return;
  }

  let response = await auth.clone().send_announce();
  ann_link = response.get_link();

  update_container(router.announcement);

  subs = [];

  let ann_addr = ann_link.to_string().split(":");
  setText("announcement-address",
      "Channel Address: " + ann_addr[0] + "<br /><br />Announcement ID: " + ann_addr[1]);
}

async function subscribe() {
  if (!streams) {
    console.log("Not yet loaded...");
    return;
  }

  // Open chat button, disabled until users exist
  let button = document.getElementById("toggle-chat");
  button.disabled = true;

  let form = document.forms.sub_settings;
  let options = new streams.SendOptions(
      send_options.depth,
      send_options.local_pow,
      send_options.threads
  )

  let sub = new streams.Subscriber(
      node_url,
      form["seed_b"].value,
      options
  );

  await sub.clone().receive_announcement(ann_link.copy());

  let response = await sub.clone().send_subscribe(ann_link.copy());
  let sub_link = response.get_link();
  console.log("sub link: " + sub_link.to_string());
  await auth.clone().receive_subscribe(sub_link);

  // store subscriber instance
  subs.push({name: form["username_entry"].value, pk: sub.clone().get_public_key(), user: sub});

  // set default sender if none exists yet
  if(sender_id === null) {
    sender_id = form["username_entry"].value;
  }

  addUserButton(form["username_entry"].value);
  button.disabled = false;
}


async function start_chat_channel() {
  let keyload_response = await auth.clone().send_keyload_for_everyone(ann_link.copy());
  keyload_link = keyload_response.get_link();
  last_link = keyload_link;

  start_fetch();
  update_container(router.chat);
}

function start_fetch(){
  fetching = true;
  fetch_id = window.setInterval(function(){
    fetch_messages();
  }, 2000);
}

async function fetch_messages() {
  // Don't try to use while in use
  if(busy) {
    console.log("Busy...");
    return;
  }
  console.log("Fetching...");
  busy = true;

  let next_msgs = await auth.clone().fetch_next_msgs()
  if(next_msgs.length === 0) {
      exists = false;
      busy = false;
      return;
  }

  for(var i = 0; i < next_msgs.length; i++) {
      addMessage(next_msgs[i]);
  }

  busy = false;
  last_link = next_msgs[next_msgs.length-1].get_link();
}

function addUserButton(sub_id) {
  var new_contact = document.createElement('div');
  new_contact.className = "center";

  var button = document.createElement("button");
  button.onclick = function() {sendMenuToggle(sub_id)};
  button.className = "user-button center dark white-text";
  button.innerHTML = sub_id;
  new_contact.appendChild(button);

  var user_buttons = document.getElementById("users-choose");
  user_buttons.appendChild(new_contact)
}

function addMessage(message){
  let inner_message = message.get_message();
  let masked = inner_message.get_masked_payload();
  let inner_pub = inner_message.get_public_payload();

  if (inner_pub.length === 0 && masked.length === 0) {
    console.log("Empty message");
    return;
  }

  let doc = document.getElementById("messages");
  let msg_id = message.get_link().msg_id;
  let pk = message.get_message().get_pk();
  let user = subs.find(s => s.pk === pk);
  count += 1;

  // Msg Container
  var newMsg = document.createElement('div');
  newMsg.className = "message";

  // Msg id
  var addr = document.createElement('div');
  addr.className = "address";
  addr.id = "addr_" + msg_id;
  addr.innerHTML = "Id: " + msg_id.substring(0, 10);
  newMsg.appendChild(addr);

  // Sending user
  var sender = document.createElement('div');
  sender.className = "sender";
  sender.id = user.name + "_" + count;
  sender.innerHTML = "Sender: " + user.name;
  newMsg.appendChild(sender);

  // Public payload
  var pub = document.createElement('div');
  pub.className = "public message-wrap";
  pub.id = "public_" + msg_id;
  pub.innerHTML = "Public: " + streams.from_bytes(inner_pub);


  // Masked payload
  var mask = document.createElement('div');
  mask.id = "masked_" + msg_id;
  mask.className = "masked message-wrap";
  mask.innerHTML = "Masked: " + streams.from_bytes(masked);
  mask.hidden = true;

  // Masked payload toggle button
  let masked_button = document.createElement('button');
  masked_button.className = "msg-button dark white-text";
  masked_button.id = "masked_button_" + msg_id;
  masked_button.innerHTML = "See Masked Message";
  masked_button.onclick = function() { messageToggle(msg_id) };

  if (masked.length === 0) {
    masked_button.disabled = true;
    masked_button.innerHTML = "No Masked Message";
  }

  newMsg.appendChild(pub);
  newMsg.appendChild(mask);
  newMsg.appendChild(masked_button);

  // Add it all
  doc.appendChild(newMsg);
}

async function send_message() {
  if ((typeof exists === 'undefined') || exists !== false || (typeof auth === 'undefined')){
    alert("Author still loading... wait for sync to complete");
    return;
  }
  let form = document.getElementById("msg-settings");

  let msg = form["message"].value;
  let masked = form["masked"].value === "true";

  let public_msg = streams.to_bytes(masked ? "" : msg);
  let masked_msg = streams.to_bytes(masked ? msg : "");

  console.log(last_link);
  console.log(keyload_link);
  let link = last_link ? last_link : (keyload_link ? keyload_link : null);
  if (!link){
    alert("We are still loading... wait for sync to complete");
    return;
  }

  let response;

  for(var x=0;x<subs.length;x++) {
    if (subs[x].name === sender_id) {
      let sub = subs[x].user;
      await sub.clone().sync_state();
      response = await sub.clone().send_signed_packet(link, public_msg, masked_msg);
      last_link = response.get_link();
    }
  }

}

function _update_last(link){
  last_link = link;
  setText("latest-msg-link", link.to_string())
}

function setText(id, text) {
  element1 = document.getElementById(id);
  element1.innerHTML = text;
}

function menuToggle() {
  let menu = document.getElementById("menu-wrapper");
  menu.hidden = !menu.hidden;
}

function sendMenuToggle(sub) {
  sender_id = sub;
  let button = document.getElementById("sendMessage");
  button.disabled = false;
}

function feedToggle() {
  let left = document.getElementById("container-left");
  if(left.className.includes("left")) {
    left.className = "container full"
  } else {
    left.className = "container left"
  }

  let right = document.getElementById("container-right");
  right.hidden = !right.hidden;

  let hiddenToggle = document.getElementById("feed-toggle-hidden");
  hiddenToggle.hidden = !hiddenToggle.hidden;
}

function messageToggle(msgid) {
  let masked = document.getElementById("masked_" + msgid);
  let pub = document.getElementById("public_" + msgid);
  let masked_button = document.getElementById("masked_button_" + msgid);
  masked.hidden = !masked.hidden;
  pub.hidden = !pub.hidden;

  if (masked_button.innerHTML !== "See Masked Message") {
    masked_button.innerHTML = "See Masked Message";
  } else {
    masked_button.innerHTML = "See Public Message";
  }
}

function update_container(next_id) {
  let previous = document.getElementById(page_id);
  let next = document.getElementById(next_id);

  previous.hidden = !previous.hidden;
  next.hidden = !next.hidden;
  page_id = next_id;
}

