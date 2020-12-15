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
    form["url"],
    form["seed_a"],
    options,
    form["multi"]
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
    form["url"],
    form["seed_b"],
    options,
    form["multi"]
  );
}

function copy_link() {
  var range = document.createRange();
  range.selectNode(document.getElementById("announce-link"));
  window.getSelection().addRange(range);

  document.execCommand("copy");

  alert(
    "Copied the text: " + document.getElementById("announce-link").innerHTML
  );
}

async function announce() {
  if (!streams) {
    console.log("Not yet loaded...");
    return;
  }

  let ann_link = await auth.send_announce();
  setText("announce-link", ann_link.substr(1, ann_link.length - 2));
}

async function subscribe(fieldname) {
    let link = document.getElementById(fieldname)
    if (link.value !== 104){
        alert(
            "Subscribe link is not correct (105 characters required)"
          );
          return;
    }

    sub.subscribe(new streams.Address(link));
}

async function send_keyload(fieldname){
    //auth.receive_subscribe(link)
    let addr = auth.channel_address();
    console.log(addr);
}

async function unsubscribe(fieldname){

}

async function fetch_messages() {}

async function send_message(form) {
  let msg = form["message"];
}

function setText(id, text) {
  element1 = document.getElementById(id);
  element1.innerHTML = text;
}
