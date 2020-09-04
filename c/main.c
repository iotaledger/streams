#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include "include/streams.h"

int main() {
    bool multi_branching = false;
    char seed[10] = "";

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


    printf("Sending keyload\n");
    message_links_t *keyload_links = auth_share_keyload_for_everyone(auth, ann_link);
    printf("Made a keyload\n\n");

    printf("Fetching Transaction\n");
    address_t *keyload_link = get_msg_link(keyload_links);
    printf("Got the link to fetch\n");
    message_t *keyload_packet = get_transaction(keyload_link);
    printf("Got the transaction\n\n");


    char public_payload[] = "A public payload woopeee";
    char private_payload[] = "A private payload uhu";

    printf("Sending tagged packet\n");
    message_links_t *tagged_packet_links = auth_tag_packet(auth, keyload_links, public_payload, private_payload);
    printf("Made a tagged packet\n\n");

    printf("Sending signed packet\n");
    message_links_t *signed_packet_links = auth_sign_packet(auth, tagged_packet_links, public_payload, private_payload);
    printf("Made a signed packet\n\n");

    printf("Fetching Transaction\n");
    address_t *signed_packet_link = get_msg_link(signed_packet_links);
    printf("Got the link to fetch\n");
    message_t *signed_packet = get_transaction(signed_packet_link);
    printf("Got the transaction\n\n");

    return 0;
}