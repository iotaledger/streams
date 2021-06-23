#include "iota_streams/channels.h"
#include <stdio.h>
#include <time.h>

void rand_seed(char *seed, size_t n)
{
  static char const alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+";
  srand((unsigned int)time(NULL));

  if (seed && n)
  for(; --n; )
  {
    int key = rand() % (sizeof(alphabet) - 1);
    *seed++ = alphabet[key];
  }
  *seed = '\0';
}

int main()
{
  printf("Starting c bindings test\n\n");
  transport_t *tsp = NULL;
  uint8_t multi_branching = 1;
  char seed[] = "bindings test seed";
  char const encoding[] = "utf-8";
  const size_t size = 1024;

  rand_seed(seed, sizeof(seed));

#ifdef IOTA_STREAMS_CHANNELS_CLIENT
  char const *env_url = getenv("URL");
  char const *url = env_url ? env_url : "http://localhost:14265";

  printf("Loading using node: %s\n\n", url);
  tsp = tsp_client_new_from_url(url);
#else
  printf("Doing local tests using bucket transport (offline) \n");
  tsp = tsp_new();
#endif
  printf("Making author with %s\n", seed);
  author_t *auth = auth_new(seed, encoding, size, multi_branching, tsp);
  printf("Made an author... ");

  // Fetch Application instance
  {
    channel_address_t const *appinst = auth_channel_address(auth);
    // `auth_channel_address` does not allocate, no need to drop `appinst`
    char const *appinst_str = get_channel_address_str(appinst);
    printf("With AppInst: %s\n\n", appinst_str);
    drop_str(appinst_str);
    auth_is_multi_branching(auth);
    auth_get_public_key(auth);
  }

  buffer_t bytes = auth_export(auth, "my_password");
  printf("Pointer: %p %zu\n", bytes.ptr, sizeof(bytes.ptr));
  printf("Size of bytes: %zu\nBytes: \n", bytes.size);

  uint8_t *new_bytes = malloc(sizeof(uint8_t) * bytes.size);

  for (int i=0; i<bytes.size; i++){
    printf("%i ", bytes.ptr[i]);
    new_bytes[i] = bytes.ptr[i];
  }
  printf("\nPointer: %p\n", bytes.ptr);

  author_t *auth_new = auth_import(new_bytes, bytes.size, "my_password", tsp);

  printf("Made new auth\n");
  // Fetch Application instance
  {
    channel_address_t const *appinst = auth_channel_address(auth_new);
    // `auth_channel_address` does not allocate, no need to drop `appinst`
    char const *appinst_str = get_channel_address_str(appinst);
    printf("With AppInst: %s\n\n", appinst_str);
    drop_str(appinst_str);
  }

  return 0;
  // sending announcement
  printf("Sending announcement\n");
  address_t const *ann_link = auth_send_announce(auth);
  printf("Made an announcement. \nSuccess: %d\n\n", ann_link != NULL);

  // Test conversions
  printf("Converting announcement link to strings\n");
  char const *ann_address_inst_str = get_address_inst_str(ann_link);
  char const *ann_address_id_str = get_address_id_str(ann_link);
  printf("Appinst: %s,  \nMsgId: %s\n", ann_address_inst_str, ann_address_id_str);

  char const connector[] = ":";
  char buffer[sizeof(*ann_address_inst_str) + sizeof(*ann_address_id_str) + 1];

  strcat(buffer, ann_address_inst_str);
  strcat(buffer, connector);
  strcat(buffer, ann_address_id_str);
  //printf("Buffer length: %ld\n", sizeof(buffer));

  printf("Converted to string: %s\n", buffer);

  address_t *ann_link_copy = address_from_string(buffer);
  char const *ann_cpy_inst_str = get_address_inst_str(ann_link_copy);
  char const *ann_cpy_id_str = get_address_id_str(ann_link_copy);

  printf("Converted back to link.\nOriginal: %s:%s\nConverted: %s:%s\n\n",
         ann_address_inst_str, ann_address_id_str,
         ann_cpy_inst_str, ann_cpy_id_str);

  drop_str(ann_address_inst_str);
  drop_str(ann_address_id_str);
  drop_str(ann_cpy_inst_str);
  drop_str(ann_cpy_id_str);

  printf("Converting link to tangle index\n");
  char const *link_index = get_address_index_str(ann_link_copy);

  printf("Tangle index: %s", link_index);

  drop_str(link_index);
  drop_address(ann_link_copy);


  // Subscriber
  char const sub_seed_a[] = "SUBSCRIBERA9SEED";
  printf("Making Sub A with %s\n", sub_seed_a);
  subscriber_t *subA = sub_new("sub_seed_a", encoding, size, tsp);
  printf("Made a sub A... \n");

  char const sub_seed_b[] = "SUBSCRIBERB9SEED";
  printf("Making Sub B with %s\n", sub_seed_b);
  subscriber_t *subB = sub_new("sub_seed_b", encoding, size, tsp);
  printf("Made a sub B... \n");

  printf("Unwrapping announcement packet... \n");
  sub_receive_announcement(subA, ann_link);
  sub_receive_announcement(subB, ann_link);
  printf("Announcement unwrapped, generating subscription message...\n");
  address_t const *sub_a_link = sub_send_subscribe(subA, ann_link);
  address_t const *sub_b_link = sub_send_subscribe(subB, ann_link);

  printf("Subscription request sent... \nSuccess: %d\n\n", sub_a_link != NULL && sub_b_link != NULL);

  printf("Accepting Sub A to author subscription list\n");
  auth_receive_subscribe(auth, sub_a_link);
  printf("Accepting Sub B to author subscription list\n");
  auth_receive_subscribe(auth, sub_b_link);

  printf("Subs A and B subscribed!\n\n");

  // Keyload share packet

  printf("Sending keyload\n");
  message_links_t keyload_links = auth_send_keyload_for_everyone(auth, ann_link);
  printf("Made a keyload\n\n");

  printf("Subscriber unwrapping keyload\n");
  printf("Fetching Transaction\n");
  address_t const *keyload_packet_sequence_link = keyload_links.seq_link;
  printf("Got the link to fetch\n");
  address_t const *keyload_packet_address = sub_receive_sequence(subA, keyload_packet_sequence_link);

  sub_receive_keyload(subA, keyload_packet_address);
  printf("Subscriber A handled keyload\n\n");

  // Fetch next message ids and process keyload - Sub B
  printf("Subscriber B fetching next messages\n");
  next_msg_ids_t const *msgIds = sub_gen_next_msg_ids(subB);
  printf("Got next message ids? Success: %d\n", msgIds != NULL);
  message_links_t sub_received_links = sub_receive_keyload_from_ids(subB, msgIds);
  printf("Subscriber B unwrapped keyload? %d\n\n", &sub_received_links != NULL);
  drop_next_msg_ids(msgIds);
  drop_links(sub_received_links);

  char const public_payload[] = "A public payload woopeee";
  char const masked_payload[] = "A masked payload uhu";

  // Signed packet
  printf("Sending signed packet\n");
  message_links_t signed_packet_links = auth_send_signed_packet(
    auth, keyload_links,
    (uint8_t const *)public_payload, sizeof(public_payload),
    (uint8_t const *)masked_payload, sizeof(masked_payload));
  printf("Made a signed packet\n\n");

  printf("Fetching Transaction\n");
  address_t const *signed_packet_sequence_link = signed_packet_links.seq_link;
  printf("Got the link to fetch\n");
  address_t const *signed_packet_address = sub_receive_sequence(subA, signed_packet_sequence_link);

  printf("Subscriber unwrapping Signed packet\n");
  packet_payloads_t signed_packet_response = sub_receive_signed_packet(subA, signed_packet_address);
  printf("public: '%s' \tmasked: '%s'\n", signed_packet_response.public_payload.ptr, signed_packet_response.masked_payload.ptr);
  printf("Subscriber handled Signed packet\n");

  // Tagged packet
  printf("Sending tagged packet\n");
  message_links_t tagged_packet_links = auth_send_tagged_packet(
    auth, signed_packet_links,
    (uint8_t const *)public_payload, sizeof(public_payload),
    (uint8_t const *)masked_payload, sizeof(masked_payload));
  printf("Made a tagged packet\n\n");

  printf("Fetching Transaction\n");
  address_t const *tagged_packet_sequence_link = tagged_packet_links.seq_link;
  printf("Got the link to fetch\n");

  address_t const *tagged_packet_address = sub_receive_sequence(subA, tagged_packet_sequence_link);
  printf("Subscriber unwrapping Tagged packet\n");
  packet_payloads_t tagged_packet_response = sub_receive_tagged_packet(subA, tagged_packet_address);
  printf("public: '%s' \tmasked: '%s'\n", signed_packet_response.public_payload.ptr, signed_packet_response.masked_payload.ptr);
  printf("Subscriber handled Tagged packet\n");

  // Several messages

  printf("Sending 3 tagged packets\n");
  char const public_1[] = "Public 1";
  char const public_2[] = "Public 2";
  char const public_3[] = "Public 3";
  char const masked_1[] = "Masked 1";
  char const masked_2[] = "Masked 2";
  char const masked_3[] = "Masked 3";

  message_links_t tagged_packet_1_links = auth_send_tagged_packet(
    auth, tagged_packet_links, (uint8_t const *)public_1, sizeof(public_1), (uint8_t const *)masked_1, sizeof(masked_1));
  message_links_t tagged_packet_2_links = auth_send_tagged_packet(
    auth, tagged_packet_links, (uint8_t const *)public_2, sizeof(public_2), (uint8_t const *)masked_2, sizeof(masked_2));
  message_links_t tagged_packet_3_links = auth_send_tagged_packet(
    auth, tagged_packet_links, (uint8_t const *)public_3, sizeof(public_3), (uint8_t const *)masked_3, sizeof(masked_3));
  printf("Sent\n");

  printf("Subscriber fetching messages...\n");
  unwrapped_messages_t const *message_returns = sub_sync_state(subA);
  printf("Found messages\n");

  size_t x;
  for(x = 0; x < 3; x++)
  {
    packet_payloads_t response = get_indexed_payload(message_returns, x);
    printf("Unpacking message...\npublic: '%s' \tmasked: '%s'\n", response.public_payload.ptr, response.masked_payload.ptr);
    //`get_indexed_payload` does not allocate, no need to drop `response`
  }


  printf("\n\n ----------------------- \n");
  printf("Beginning author recovery...\n");

  author_t *recovered_auth = auth_recover(seed, ann_link, multi_branching, tsp);

  user_state_t const *recovered_auth_state = auth_fetch_state(recovered_auth);
  user_state_t const *original_auth_state = auth_fetch_state(auth);

  public_key_t const *recovered_auth_pk = auth_get_public_key(recovered_auth);
  public_key_t const *original_auth_pk = auth_get_public_key(auth);

  address_t const *recovered_state_link = get_link_from_state(recovered_auth_state, recovered_auth_pk);
  address_t const *original_state_link = get_link_from_state(original_auth_state, original_auth_pk);

  char const *recovered_link_id = get_address_id_str(recovered_state_link);
  char const *original_link_id = get_address_id_str(original_state_link);

  printf("Recovered/Original state links: %s, %s\n", recovered_link_id, original_link_id);

  drop_user_state(recovered_auth_state);
  drop_user_state(original_auth_state);
  drop_address(ann_link);
  drop_address(recovered_state_link);
  drop_address(original_state_link);
  drop_address(sub_a_link);
  drop_address(sub_b_link);
  drop_links(keyload_links);
  drop_address(keyload_packet_address);
  drop_links(signed_packet_links);
  drop_address(signed_packet_address);
  drop_payloads(signed_packet_response);
  drop_links(tagged_packet_links);
  drop_address(tagged_packet_address);
  drop_payloads(tagged_packet_response);
  drop_links(tagged_packet_1_links);
  drop_links(tagged_packet_2_links);
  drop_links(tagged_packet_3_links);
  drop_unwrapped_messages(message_returns);

  sub_drop(subA);
  auth_drop(auth);
  auth_drop(recovered_auth);
  tsp_drop(tsp);
  return 0;
}
