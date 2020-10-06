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

typedef struct MsgReturn msgreturn_t;

typedef struct MessageReturns messagereturns_t;

typedef struct PayloadResponse {
    char* public_payload;
    char* private_payload;
} payload_response_t;

extern char *get_address_inst_str(address_t *address);
extern char *get_address_id_str(address_t *address);
extern address_t *auth_send_announce(author_t *author);
extern void *auth_receive_subscribe(author_t * author, address_t *address);

extern message_t *get_transaction(address_t *link_to);
extern messagereturns_t *auth_fetch_next_transaction(author_t *author);


typedef struct MessageLinks message_links_t;
extern message_links_t *auth_send_keyload(author_t *author, address_t *link_to, pskids_t *psk_ids, pubkeywrap_t ke_pks);
extern message_links_t *auth_send_keyload_for_everyone(author_t *author, address_t *link_to);
extern message_links_t *auth_send_tagged_packet(author_t *author, message_links_t *link_to, char *public_payload, char *private_payload);
extern message_links_t *auth_send_signed_packet(author_t *author, message_links_t *link_to, char *public_payload, char *private_payload);
extern payload_response_t *auth_receive_tagged_packet(author_t *author, address_t *address) ;
extern address_t auth_receive_sequence(author_t *author, address_t *address);
extern messagereturns_t *auth_fetch_next_msgs(author_t *author);
extern messagereturns_t *auth_sync_state(author_t *author);
extern msgreturn_t *auth_receive_msg(author_t *author, address_t *address);
extern nextmsgid_t *auth_gen_next_msg_ids(author_t *author);
extern pubkey_t *auth_get_pk(author_t *author);

extern address_t *get_msg_link(message_links_t *message_links);
extern address_t *get_seq_link(message_links_t *message_links);

typedef struct Subscriber subscriber_t;
extern appinst_t *sub_channel_address(subscriber_t *subscriber);
extern subscriber_t *sub_new(char seed[], char encoding[], size_t payload_length);
extern void *sub_receive_announce(subscriber_t *subscriber, address_t *address);
address_t *sub_send_subscribe(subscriber_t *subscriber, address_t *announcement_link);
address_t *sub_get_message_link(subscriber_t *subscriber, address_t *address);
extern void *sub_receive_keyload(subscriber_t *subscriber, address_t *address);
extern address_t *sub_receive_sequence(subscriber_t *subscriber, address_t *address);
extern messagereturns_t *sub_fetch_next_msgs(subscriber_t *subscriber);
extern messagereturns_t *sub_sync_state(subscriber_t *subscriber);
extern msgreturn_t *sub_receive_msg(subscriber_t *subscriber, address_t *address);
extern nextmsgid_t *sub_gen_next_msg_ids(subscriber_t *subscriber);
extern pubkey_t *sub_get_pk(subscriber_t *subscriber);


extern payload_response_t *sub_receive_signed_packet(subscriber_t *subscriber, address_t *address);
extern payload_response_t *sub_receive_tagged_packet(subscriber_t *subscriber, address_t *address);

extern unsigned int auth_get_branching_flag(author_t * author);
extern unsigned int sub_get_branching_flag(subscriber_t * subscriber);
extern unsigned int *sub_is_registered(subscriber_t *subscriber);
extern void *sub_unregister(subscriber_t *subscriber);