// auth
// sub

// keyload_link
// last_link

// fetching true/false

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

  let response = await auth.clone().send_keyload_for_everyone(ann_link);
  keyload_link = response.get_link();
  setText("latest-msg-link", keyload_link.to_string())

  console.log("keyload link: " + keyload_link.to_string());
  start_fetch();
}

async function unsubscribe(fieldname) {}

function stop_start() {
  let btn = document.getElementById("stopstart");
  if (btn.value === "Stop"){
    btn.value = "Start";
    stop_fetch();
  } else {
    btn.value = "Stop";
    start_fetch();
  }
}

function start_fetch(){
  fetching = true;
  let amount = document.getElementById("auto_fetch").value;
  let interval = amount * 1000;
  fetch_id = window.setInterval(function(){
    fetch_messages();
  }, interval);
}

function stop_fetch(){
  fetching = false;
  clearInterval(fetch_id);
}

async function fetch_messages() {
  console.log("fetching...");

  let next_msgs = await auth.clone().fetch_next_msgs();

  if(next_msgs.length === 0) {
      exists = false
      return;
  }

  for(var i = 0; i < next_msgs.length; i++) {
      addMessage("messages", next_msgs[i]);
  }

  last_link = next_msgs[next_msgs.length-1].get_link();
}

function addMessage(divId, message){
  let doc = document.getElementById(divId);
  let msg_id = message.get_link().msg_id;

  var newMsg = document.createElement('div');
  newMsg.className = "message";

  // Msg id
  var li = document.createElement('div');
  var addr_label = document.createElement('label');
  addr_label.setAttribute("for","addr_" + msg_id);
  addr_label.innerHTML = "Msg id: ";
  li.appendChild(addr_label);

  var addr = document.createElement('lavel');
  addr.className = "address";
  addr.id = "addr_" + msg_id;
  addr.innerHTML = msg_id;
  li.appendChild(addr);
  newMsg.appendChild(li);

  // Public payload
  li = document.createElement('div');
  var pub_label = document.createElement('label');
  pub_label.setAttribute("for","public_" + msg_id);
  pub_label.innerHTML = "public: ";
  li.appendChild(pub_label);

  var pub = document.createElement('label');
  pub.className = "public";
  pub.id = "public_" + msg_id;
  pub.innerHTML = streams.from_bytes(message.get_message().get_public_payload());
  li.appendChild(pub);
  newMsg.appendChild(li);

  // Masked payload
  li = document.createElement('div');
  var mask_label = document.createElement('label');
  mask_label.setAttribute("for","masked_" + msg_id);
  mask_label.innerHTML = "masked: ";
  li.appendChild(mask_label);

  var mask = document.createElement('label');
  mask.id = "masked_" + msg_id;
  mask.className = "masked";
  mask.innerHTML = streams.from_bytes(message.get_message().get_masked_payload());
  li.appendChild(mask);
  newMsg.appendChild(li);

  // Add it all
  doc.appendChild(newMsg);
  doc.appendChild(document.createElement('hr'));
}

async function send_message(form) {
  if ((typeof exists === 'undefined') || exists !== false || (typeof auth === 'undefined')){
    alert("Author still loading... wait for sync to complete");
    return;
  }

  let msg = form["message"].value;
  let masked = form["masked"].value === "true";
  let send_as_auth = form["msg_who"].value === "true";

  let public_msg = streams.to_bytes(masked ? "" : msg);
  let masked_msg = streams.to_bytes(masked ? msg : "");

  let link = (typeof last_link !== 'undefined') ? last_link : keyload_link;
  let response;
  if (send_as_auth){
    console.log("Author Sending tagged packet");
    await auth.clone().sync_state();
    response = await auth.clone().send_tagged_packet(link, public_msg, masked_msg);
  } else {
    console.log("Subscriber Sending tagged packet");
    await sub.clone().sync_state();
    response = await sub.clone().send_tagged_packet(link, public_msg, masked_msg);
  }

  last_link = response.get_link();
  setText("latest-msg-link", last_link.to_string())
  console.log("Tag packet at: ", last_link.to_string());
}

function setText(id, text) {
  element1 = document.getElementById(id);
  element1.innerHTML = text;
}
