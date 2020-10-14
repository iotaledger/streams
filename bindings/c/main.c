#include "iota_streams/channels.h"
#include <stdio.h>
#include <time.h>

#define IOTA_STREAMS_CHANNELS_CLIENT 1

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
  transport_t *tsp;
  uint8_t multi_branching = 1;
  char seed[] = "bindings test seed";
  char const encoding[] = "utf-8";
  const size_t size = 1024;

  rand_seed(seed, sizeof(seed));

#ifdef IOTA_STREAMS_CHANNELS_CLIENT
  char url[] = "http://brord01.mainnet.iota.cafe:14265";
  printf("Loading using node: %s\n\n", url);
  tsp = tsp_client_new_from_url(url);
  // Make sure this mwm matches the node configuration
  tsp_client_set_mwm(tsp, 14);
#else
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

  // sending announcement
  printf("Sending announcement\n");
  address_t const *ann_link = auth_send_announce(auth);
  printf("Made an announcement\n\n");

  // Subscriber
  char const sub_seed_a[] = "SUBSCRIBERA9SEED";
  printf("Making Sub A with %s\n", sub_seed_a);
  subscriber_t *subA = sub_new("sub_seed_a", encoding, size, tsp);
  printf("Made an sub A... \n");

  printf("Unwrapping announcement packet... \n");
  sub_receive_announce(subA, ann_link);
  printf("Announcement unwrapped, generating subscription message...\n");
  address_t const *sub_link = sub_send_subscribe(subA, ann_link);
  printf("Subscription request sent...\n\n");

  printf("Accepting Sub A to author subscription list\n");
  auth_receive_subscribe(auth, sub_link);

  printf("Sub A subscribed!\n\n");

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
  printf("Subscriber handled keyload\n\n");

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
  printf("public: '%s' \tmasked: '%s'\n", signed_packet_response.public_payload_ptr, signed_packet_response.masked_payload_ptr);
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
  printf("public: '%s' \tmasked: '%s'\n", signed_packet_response.public_payload_ptr, signed_packet_response.masked_payload_ptr);
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
    printf("Unpacking message...\npublic: '%s' \tmasked: '%s'\n", response.public_payload_ptr, response.masked_payload_ptr);
    //`get_indexed_payload` does not allocate, no need to drop `response`
  }

  drop_address(ann_link);
  drop_address(sub_link);
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

  auth_drop(auth);
  sub_drop(subA);
  tsp_drop(tsp);
  return 0;
}
