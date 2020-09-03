#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include "include/streams.h"

int main() {
    bool multi_branching = false;
    char seed[] = "ABCDEFGHI";

    char encoding[] = "utf-8";

    const size_t size = 1024;

    printf("Making author with %s, %s, %ld, %d\n", seed, encoding, size, multi_branching);
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

    printf("Sending keyload\n");
    message_links_t *keyload_links = auth_share_keyload_for_everyone(auth, ann_link);
    printf("Made a keyload\n\n");

    char public_payload[] = "A public payload woopeee";
    char private_payload[] = "A private payload uhu";

    printf("Sending tagged packet\n");
    message_links_t *tagged_packet_links = auth_tag_packet(auth, keyload_links, public_payload, private_payload);
    printf("Made a tagged packet\n\n");

    printf("Sending signed packet\n");
    message_links_t *signed_packet_links = auth_sign_packet(auth, tagged_packet_links, public_payload, private_payload);
    printf("Made a signed packet\n\n");


    return 0;
}