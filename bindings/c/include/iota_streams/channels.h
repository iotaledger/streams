#ifndef IOTA_STREAMS_CHANNELS_H
#define IOTA_STREAMS_CHANNELS_H

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

typedef enum Err {
  ERR_OK,
  ERR_NULL_ARGUMENT,
  ERR_BAD_ARGUMENT,
  ERR_OPERATION_FAILED,
} err_t;

typedef struct Address address_t;
extern void drop_address(address_t const *);
extern address_t *address_from_string(char const *addr_str);

typedef struct ChannelAddress channel_address_t;
typedef struct MsgId msgid_t;
typedef struct PublicKey public_key_t;
typedef struct PskId psk_id_t;
typedef struct PskIds psk_ids_t;
typedef struct KePks ke_pks_t;
typedef struct Identifier identifier_t;
extern void drop_id(identifier_t const *);

typedef struct NextMsgIds next_msg_ids_t;
extern void drop_next_msg_ids(next_msg_ids_t const *);

typedef struct UserState user_state_t;
extern void drop_user_state(user_state_t const *);

typedef struct UnwrappedMessage unwrapped_message_t;
extern void drop_unwrapped_message(unwrapped_message_t const *);

typedef struct UnwrappedMessages unwrapped_messages_t;
extern void drop_unwrapped_messages(unwrapped_messages_t const *);

typedef struct MessageLinks {
  address_t const *msg_link;
  address_t const *seq_link;
} message_links_t;

extern void drop_links(message_links_t);

typedef struct Buffer {
  uint8_t const *ptr;
  size_t size;
  size_t cap;
} buffer_t;

extern void drop_buffer(buffer_t);

typedef struct PacketPayloads {
  buffer_t public_payload;
  buffer_t masked_payload;
} packet_payloads_t;

extern void drop_payloads(packet_payloads_t);

////////////
/// Transport
////////////
typedef struct Transport transport_t;
extern transport_t *transport_new();
extern void transport_drop(transport_t *);
#ifdef IOTA_STREAMS_CHANNELS_CLIENT
extern transport_t *transport_client_new_from_url(char const *url);
#endif

#ifdef IOTA_STREAMS_CHANNELS_CLIENT
typedef enum LedgerInclusionState {
    LIS_Conflicting = 0,
    LIS_Included = 1,
    LIS_NoTransaction = 2,
} ledger_inclusion_state_t;

typedef struct MessageMetadata {
    char message_id[129];
    char parent_message_ids[129][2];
    bool is_solid;
    uint32_t referenced_by_milestone_index;
    uint32_t milestone_index;
    ledger_inclusion_state_t ledger_inclusion_state;
    uint8_t conflict_reason;
    bool should_promote;
    bool should_reattach;
    uint32_t field_flags;
} msg_metadata_t;

typedef struct Milestone {
    uint32_t milestone_index;
    char message_id[129];
    uint64_t timestamp;
} milestone_t;

typedef struct TransportDetails {
    msg_metadata_t msg_metadata;
    milestone_t milestone;
} transport_details_t;

extern err_t transport_get_link_details(transport_details_t *details, transport_t *transport, address_t const *link);
#endif

////////////
/// Author
////////////
typedef struct Author author_t;

extern err_t auth_new(author_t **auth, char const *seed, uint8_t implementation, transport_t *transport);
extern err_t auth_recover(author_t **auth, char const *seed, address_t const *announcement, uint8_t implementation, transport_t *transport);
extern void auth_drop(author_t *);

extern err_t auth_import(author_t **auth, buffer_t buffer, char const *password, transport_t *transport);
extern err_t auth_export(buffer_t *buf, author_t const *author, char const *password);

extern err_t auth_channel_address(channel_address_t const **addr, author_t const *author);
extern err_t auth_announcement_link(address_t const **addr, author_t const *author);
extern err_t auth_is_multi_branching(uint8_t *flag, author_t const *author);
extern err_t auth_get_public_key(public_key_t const **pk, author_t const *author);
extern err_t auth_get_id(identifier_t const **id, author_t const *author);

// Announce
extern err_t auth_send_announce(address_t const **addr, author_t *author);
// Keyload
extern err_t auth_send_keyload_for_everyone(message_links_t *links, author_t *author, address_t const *link_to);
extern err_t auth_send_keyload(message_links_t *links, author_t *author, address_t const *link_to, psk_ids_t *psk_ids, ke_pks_t ke_pks);

// Subscribe
extern err_t auth_receive_subscribe(author_t *author, address_t const *address);
extern err_t auth_receive_unsubscribe(author_t *author, address_t const *address);
extern err_t auth_store_new_subscriber(author_t *author, public_key_t const *public_key);
extern err_t auth_remove_subscriber(author_t *author, public_key_t const *public_key);

// Tagged Packets
extern err_t auth_send_tagged_packet(message_links_t *links, author_t *author, message_links_t link_to, uint8_t const *public_payload_ptr, size_t public_payload_size, uint8_t const *masked_payload_ptr, size_t masked_payload_size);
extern err_t auth_receive_tagged_packet(packet_payloads_t *payloads, author_t *author, address_t const *address);
// Signed Packets
extern err_t auth_send_signed_packet(message_links_t *links, author_t *author, message_links_t link_to, uint8_t const *public_payload_ptr, size_t public_payload_size, uint8_t const *masked_payload_ptr, size_t masked_payload_size);
extern err_t auth_receive_signed_packet(packet_payloads_t *payloads, author_t *author, address_t const *address) ;
// Sequence Message (for multi branch use)
extern err_t auth_receive_sequence(address_t const **seq, author_t *author, address_t const *address);
// MsgId generation
extern err_t auth_gen_next_msg_ids(next_msg_ids_t const **ids, author_t *author);
// Generic Processing
extern err_t auth_receive_msg(unwrapped_message_t const **msg, author_t *author, address_t const *address);
extern err_t auth_receive_msg_by_sequence_number(unwrapped_message_t const **msg, author_t *author, address_t const *anchor_address, size_t *msg_num);
// Fetching/Syncing
extern err_t auth_fetch_next_msgs(unwrapped_messages_t const **umsgs, author_t *author);
extern err_t auth_fetch_prev_msg(unwrapped_message_t const **umsg, author_t *author, address_t const *address);
extern err_t auth_fetch_prev_msgs(unwrapped_messages_t const **umsgs, author_t *author, address_t const *address, size_t num_msgs);
extern err_t auth_sync_state(unwrapped_messages_t const **umsgs, author_t *author);
extern err_t auth_fetch_state(user_state_t const **state, author_t *author);
extern err_t auth_reset_state(author_t *author);
// Store Psk
extern err_t auth_store_psk(psk_id_t const **pskid, author_t *author, char const *psk);
extern err_t auth_remove_psk(author_t *author, char const *pskid);


/////////////
// Subscriber
/////////////
typedef struct Subscriber subscriber_t;
extern err_t sub_new(subscriber_t **sub, char const *seed, transport_t *transport);
extern err_t sub_import(subscriber_t **sub, buffer_t buffer, char const *password, transport_t *transport);
extern err_t sub_export(buffer_t *buf, subscriber_t const *subscriber, char const *password);
extern void sub_drop(subscriber_t *);

extern err_t sub_channel_address(channel_address_t const **addr, subscriber_t const *subscriber);
extern err_t sub_announcement_link(address_t const **addr, subscriber_t const *subscriber);
extern err_t sub_is_multi_branching(uint8_t *flag, subscriber_t const *subscriber);
extern err_t sub_get_public_key(public_key_t const **pk, subscriber_t const *subscriber);
extern err_t sub_get_id(identifier_t const **id, subscriber_t const *subscriber);
extern err_t sub_author_public_key(public_key_t const **pk, subscriber_t const *subscriber);

// Registration state
extern uint8_t sub_is_registered(subscriber_t const *subscriber);
extern void sub_unregister(subscriber_t *subscriber);

// Announce
extern err_t sub_receive_announce(subscriber_t *subscriber, address_t const *address);
// Subscribe
extern err_t sub_send_subscribe(address_t const **link, subscriber_t *subscriber, address_t const *announcement_link);
extern err_t sub_send_unsubscribe(address_t const **link, subscriber_t *subscriber, address_t const *subscription_link);
// Keyload
extern err_t sub_receive_keyload(uint8_t const **access, subscriber_t *subscriber, address_t const *address);
extern err_t sub_receive_keyload_from_ids(message_links_t *links, subscriber_t *subscriber, next_msg_ids_t const *next_msg_ids);
// Tagged Packets
extern err_t sub_send_tagged_packet(message_links_t *links, subscriber_t *subscriber, message_links_t link_to, uint8_t const *public_payload_ptr, size_t public_payload_size, uint8_t const *masked_payload_ptr, size_t masked_payload_size);
extern err_t sub_receive_tagged_packet(packet_payloads_t *payloads, subscriber_t *subscriber, address_t const *address);
// Signed Packets
extern err_t sub_send_signed_packet(message_links_t *links, subscriber_t *subscriber, message_links_t link_to, uint8_t const *public_payload_ptr, size_t public_payload_size, uint8_t const *masked_payload_ptr, size_t masked_payload_size);
extern err_t sub_receive_signed_packet(packet_payloads_t *payloads, subscriber_t *subscriber, address_t const *address);
// Sequence Message (for multi branch use)
extern err_t sub_receive_sequence(address_t const **address, subscriber_t *subscriber, address_t const *seq_address);
// MsgId Generation
extern err_t sub_gen_next_msg_ids(next_msg_ids_t const **ids, subscriber_t *subscriber);
// Generic Message Processing
extern err_t sub_receive_msg(unwrapped_message_t const *umsg, subscriber_t *subscriber, address_t const *address);
extern err_t sub_receive_msg_by_sequence_number(unwrapped_message_t const **msg, subscriber_t *subscriber, address_t const *anchor_address, size_t *msg_num);
// Fetching/Syncing
extern err_t sub_fetch_next_msgs(unwrapped_messages_t const **messages, subscriber_t *subscriber);
extern err_t sub_fetch_prev_msg(unwrapped_message_t const **umsg, subscriber_t *subscriber, address_t const *address);
extern err_t sub_fetch_prev_msgs(unwrapped_messages_t const **umsgs, subscriber_t *subscriber, address_t const *address, size_t num_msgs);
extern err_t sub_sync_state(unwrapped_messages_t const **messages, subscriber_t *subscriber);
extern err_t sub_fetch_state(user_state_t const **state, subscriber_t *subscriber);
extern err_t sub_reset_state(subscriber_t *subscriber);
// Store Psk
extern err_t sub_store_psk(psk_id_t const **pskid, subscriber_t *subscriber, char const *psk);
extern err_t sub_remove_psk(author_t *author, char const *pskid);


/////////////
/// Utility
/////////////
extern void drop_str(char const *str);

extern char const *get_channel_address_str(channel_address_t const *appinst);
extern char const *get_msgid_str(msgid_t const *msgid);

extern char const *get_address_inst_str(address_t const *address);
extern char const *get_address_id_str(address_t const *address);

extern char const *public_key_to_string(public_key_t *pubkey);

extern packet_payloads_t get_payload(unwrapped_message_t const *message);
extern size_t get_payloads_count(unwrapped_messages_t const *messages);
extern packet_payloads_t get_indexed_payload(unwrapped_messages_t const *messages, size_t index);

extern char const *get_address_index_str(address_t const *address);

extern address_t const *get_link_from_state(user_state_t const *state, identifier_t const *id);

extern char const *pskid_as_str(psk_id_t const *pskid);
extern void drop_pskid(psk_id_t const *pskid);

#endif //IOTA_STREAMS_CHANNELS_H


#ifndef STREAMS_DID_H
#define STREAMS_DID_H
typedef struct DIDKeypair did_keypair_t;
typedef struct DIDInfo did_info_t;
typedef struct DIDInfoWrapper did_info_wrapper_t;

extern const did_keypair_t *new_did_keypair(char const *public_key, char const *private_key);
extern const did_keypair_t *get_info_wrapper_keypair(did_info_wrapper_t const *wrapper);
extern const did_info_t *get_info_wrapper_info(did_info_wrapper_t const *wrapper);

extern err_t create_new_identity(did_info_wrapper_t const **wrapper, char const *url, uint8_t network);

extern err_t auth_new_from_did(author_t **auth, char const *seed, uint8_t implementation, transport_t *transport,did_info_t const *info, did_keypair_t const *keypair);
extern err_t sub_new_from_did(subscriber_t **sub, char const *seed, transport_t *transport,did_info_t const *info, did_keypair_t const *keypair);

extern err_t auth_recover_with_did(author_t **auth, char const *seed, address_t const *ann_address, uint8_t implementation, transport_t *transport, did_info_t  const *info);

extern void drop_info_wrapper(did_info_wrapper_t const *wrapper);
extern void drop_info(did_info_t const *info);
extern void drop_did_keypair(did_keypair_t const *kp);

#endif //STREAMS_DID_H

