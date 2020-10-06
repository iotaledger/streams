#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include "include/streams.h"

int main() {
    bool multi_branching = true;
    char seed[11] = "";

    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9";
    srand( time(NULL) );
    for (size_t n = 0; n < 10; n++) {
        int key = rand() % (int) (sizeof charset - 1);
            seed[n] = charset[key];
        }
    seed[10] = '\0';

    char encoding[] = "utf-8";

    const size_t size = 1024;

    printf("Making author with %s\n", seed);
    author_t *auth = auth_new(seed, encoding, size, multi_branching);
    printf("Made an author... ");

    // Fetch Application instance
    appinst_t *appinst = auth_channel_address(auth);
    char *appinst_str = get_appinst_str(appinst);
    printf("With AppInst: %s\n\n", appinst_str);

    // sending announcement
    printf("Sending announcement\n");
    address_t *ann_link = auth_send_announce(auth);
    printf("Made an announcement\n\n");

    // Subscriber

    char sub_seed_a[] = "SUBSCRIBERA9SEED";
    printf("Making Sub A with %s\n", sub_seed_a);
    subscriber_t *subA = sub_new("sub_seed_a", encoding, size);
    printf("Made an sub A... \n");

    printf("Unwrapping announcement packet... \n");
    sub_receive_announce(subA, ann_link);
    printf("Announcement unwrapped, generating subscription message...\n");
    address_t *sub_link = sub_send_subscribe(subA, ann_link);
    printf("Subscription request sent...\n\n");

    printf("Accepting Sub A to author subscription list\n");
    auth_receive_subscribe(auth, sub_link);

    printf("Sub A subscribed!\n\n");

    // Keyload share packet 

    printf("Sending keyload\n");
    message_links_t *keyload_links = auth_send_keyload_for_everyone(auth, ann_link);
    printf("Made a keyload\n\n");

    printf("Subscriber unwrapping keyload\n");
    printf("Fetching Transaction\n");
    address_t *keyload_packet_sequence_link = get_seq_link(keyload_links);
    printf("Got the link to fetch\n");
    address_t *keyload_packet_address = sub_receive_sequence(subA, keyload_packet_sequence_link);

    sub_receive_keyload(subA, keyload_packet_address);
    printf("Subscriber handled keyload\n\n");

    char public_payload[] = "A public payload woopeee";
    char private_payload[] = "A private payload uhu";

    // Signed packet 

    printf("Sending signed packet\n");
    message_links_t *signed_packet_links = auth_send_signed_packet(auth, keyload_links, public_payload, private_payload);
    printf("Made a signed packet\n\n");

    printf("Fetching Transaction\n");
    address_t *signed_packet_sequence_link = get_seq_link(signed_packet_links);
    printf("Got the link to fetch\n");
    address_t *signed_packet_address = sub_receive_sequence(subA, signed_packet_sequence_link);

    printf("Subscriber unwrapping Signed packet\n");
    payload_response_t *signed_packet_response = sub_receive_signed_packet(subA, signed_packet_address);
    printf("public: %s \tprivate: %s\n", signed_packet_response->public_payload, signed_packet_response->private_payload);
    printf("Subscriber handled Signed packet\n");

    // Tagged packet 

    printf("Sending tagged packet\n");
    message_links_t *tagged_packet_links = auth_send_tagged_packet(auth, signed_packet_links, public_payload, private_payload);
    printf("Made a tagged packet\n\n");

    printf("Fetching Transaction\n");
    address_t *tagged_packet_sequence_link = get_seq_link(tagged_packet_links);
    printf("Got the link to fetch\n");

    address_t *tagged_packet_address = sub_receive_sequence(subA, tagged_packet_sequence_link);
    printf("Subscriber unwrapping Tagged packet\n");
    payload_response_t *tagged_packet_response = sub_receive_tagged_packet(subA, tagged_packet_address);
    printf("public: %s \tprivate: %s\n", signed_packet_response->public_payload, signed_packet_response->private_payload);
    printf("Subscriber handled Tagged packet\n");

    // Several messages

    printf("Sending 3 tagged packets\n");
    char payload_1[] = "Message 1";
    char payload_2[] = "Message 2";
    char payload_3[] = "Message 3";

    message_links_t *tagged_packet_1_links = auth_send_tagged_packet(auth, tagged_packet_links, payload_1, private_payload);
    message_links_t *tagged_packet_2_links = auth_send_tagged_packet(auth, tagged_packet_1_links, payload_2, private_payload);
    message_links_t *tagged_packet_3_links = auth_send_tagged_packet(auth, tagged_packet_2_links, payload_3, private_payload);
    printf("Sent\n");

    printf("Subscriber fetching messages...\n");
    messagereturns_t *message_returns = sub_sync_state(subA);
    printf("Found messages\n");

    int x;
    for ( x = 0; x < 3; x++) {
        payload_response_t *response = get_indexed_payload(message_returns, x);
        printf("Unpacking message...\npublic: %s \tprivate: %s\n", response->public_payload, response->private_payload);
    }
    return 0;
}