#include <stdbool.h>
#include <string.h>


typedef struct Author author_t;
extern author_t *auth_new(char seed[], char encoding[], size_t payload_length, bool multi_branching);

typedef struct AppInst appinst_t;
extern appinst_t *auth_channel_address(author_t *author);
extern char *get_appinst_str(appinst_t *appinst);

typedef struct MsgId msgid_t;
extern char *get_msgid_str(msgid_t *msgid);

typedef struct PskIds pskids_t;

typedef struct PubKey pubkey_t;

typedef struct PubKeyWrap pubkeywrap_t;

typedef struct SeqState seqstate_t;

typedef struct NextMsgId nextmsgid_t;

typedef struct Preparsed preparsed_t;

typedef struct Address address_t;

typedef struct Message message_t;

extern char *get_address_inst_str(address_t *address);
extern char *get_address_id_str(address_t *address);
extern address_t *auth_announce(author_t *author);
extern void auth_unwrap_subscribe(author_t * author, message_t *message);

extern message_t *get_transaction(address_t *link_to);
extern message_t *auth_fetch_next_transaction(author_t *author);


typedef struct MessageLinks message_links_t;
extern message_links_t *auth_share_keyload(author_t *author, address_t *link_to, pskids_t *psk_ids, pubkeywrap_t ke_pks);
extern message_links_t *auth_share_keyload_for_everyone(author_t *author, address_t *link_to);
extern message_links_t *auth_tag_packet(author_t *author, message_links_t *link_to, char *public_payload, char *private_payload);
extern message_links_t *auth_sign_packet(author_t *author, message_links_t *link_to, char *public_payload, char *private_payload);

extern address_t *get_msg_link(message_links_t *message_links);
extern address_t *get_seq_link(message_links_t *message_links);

typedef struct Subscriber subscriber_t;
extern subscriber_t *sub_new(char seed[], char encoding[], size_t payload_length);
extern void *sub_unwrap_announce(subscriber_t *subscriber, message_t *message);
address_t *sub_subscribe(subscriber_t *subscriber, address_t *announcement_link);