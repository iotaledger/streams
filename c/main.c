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
    printf("With AppInst: %s\n", appinst_str);

    // sending announcement
    address_t *ann_link = auth_announce(auth);
    printf("Made an announcement\n");

    address_t *keyload_links = auth_share_keyload_for_everyone(auth, ann_link);
    printf("Made a keyload\n");

    return 0;
}