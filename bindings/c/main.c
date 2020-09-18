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
    address_t *ann_link = auth_announce(auth);
    printf("Made an announcement\n\n");

    printf("Fetching Transaction\n");
    message_t *ann_packet = get_transaction(ann_link);
    printf("Got the transaction\n\n");

    // Subscriber 

    char sub_seed_a[] = "SUBSCRIBERA9SEED";
    printf("Making Sub A with %s\n", sub_seed_a);
    subscriber_t *subA = sub_new("sub_seed_a", encoding, size);
    printf("Made an sub A... \n");

    printf("Unwrapping announcement packet... \n");
    sub_unwrap_announce(subA, ann_packet);
    printf("Announcement unwrapped, generating subscription message...\n");
    address_t *sub_link = sub_subscribe(subA, ann_link);
    printf("Subscription request sent...\n\n");
    
    printf("Subscription packet created, Fetching Transaction\n");
    message_t *sub_packet = get_transaction(sub_link);

    printf("Accepting Sub A to author subscription list\n");
    auth_unwrap_subscribe(auth, sub_packet);

    printf("Sub A subscribed!\n\n");

    // Keyload share packet 

    printf("Sending keyload\n");
    message_links_t *keyload_links = auth_share_keyload_for_everyone(auth, ann_link);
    printf("Made a keyload\n\n");

    printf("Subscriber unwrapping keyload\n");
    printf("Fetching Transaction\n");
    address_t *keyload_packet_sequence_link = get_seq_link(keyload_links);
    printf("Got the link to fetch\n");
    message_t *keyload_sequence_packet = get_transaction(keyload_packet_sequence_link);
    printf("Got the transaction\n\n");

    address_t *keyload_packet_address = sub_unwrap_sequence(subA, keyload_sequence_packet);

    printf("Fetching Transaction\n");
    message_t *keyload_packet = get_transaction(keyload_packet_address);
    printf("Got the transaction\n\n");

    sub_unwrap_keyload(subA, keyload_packet);
    printf("Subscriber handled keyload\n\n");

    char public_payload[] = "A public payload woopeee";
    char private_payload[] = "A private payload uhu";

    // Signed packet 

    printf("Sending signed packet\n");
    message_links_t *signed_packet_links = auth_sign_packet(auth, keyload_links, public_payload, private_payload);
    printf("Made a signed packet\n\n");

    printf("Fetching Transaction\n");
    address_t *signed_packet_sequence_link = get_seq_link(signed_packet_links);
    printf("Got the link to fetch\n");
    message_t *signed_sequence_packet = get_transaction(signed_packet_sequence_link);
    printf("Got the transaction\n\n");

    address_t *signed_packet_address = sub_unwrap_sequence(subA, signed_sequence_packet);

    printf("Fetching Transaction\n");
    message_t *signed_packet = get_transaction(signed_packet_address);
    printf("Got the transaction\n\n");

    printf("Subscriber unwrapping Signed packet\n");
    payload_response_t *signed_packet_response = sub_unwrap_signed_packet(subA, signed_packet);
    printf("public: %s private: %s\n", signed_packet_response->public_payload, signed_packet_response->private_payload);
    printf("Subscriber handled Signed packet\n");

    // Tagged packet 

    printf("Sending tagged packet\n");
    message_links_t *tagged_packet_links = auth_tag_packet(auth, signed_packet_links, public_payload, private_payload);
    printf("Made a tagged packet\n\n");

    printf("Fetching Transaction\n");
    address_t *tagged_packet_sequence_link = get_seq_link(tagged_packet_links);
    printf("Got the link to fetch\n");
    message_t *tagged_sequence_packet = get_transaction(tagged_packet_sequence_link);
    printf("Got the transaction\n\n");

    address_t *tagged_packet_address = sub_unwrap_sequence(subA, tagged_sequence_packet);

    printf("Got the link to fetch\n");
    message_t *tag_packet = get_transaction(tagged_packet_address);
    printf("Got the transaction\n\n");
    
    printf("Subscriber unwrapping Tagged packet\n");
    payload_response_t *tagged_packet_response = sub_unwrap_tagged_packet(subA, tag_packet);
    printf("public: %s private: %s\n", signed_packet_response->public_payload, signed_packet_response->private_payload);
    printf("Subscriber handled Tagged packet\n");

    return 0;
}