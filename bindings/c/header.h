#ifndef STREAMS_HEADER_H
#define STREAMS_HEADER_H
#endif //STREAMS_HEADER_H


struct AppInst;

struct MsgId;

struct Address;

struct Author;

struct Message;

struct MessageLinks;

struct MsgReturn;

struct MessageReturns;

struct PskIds;

struct PubKey;

struct PubKeyWrap;

struct SeqState; // (Address, usize[size_t])

struct NextMsgId; // vec(Pubkey, (address, usize))

struct Transport;

extern "C" {
/// Generate a new Author Instance
Author auth_new(char[] seed, char[] encoding, size_t payload_length, bool multi_branching);

/// Channel app instance.
AppInst auth_channel_address(Author *author);

char[] get_appinst_str(AppInst *appinst);

char[] get_msgid_str(MsgId *msgid);

char[] get_address_inst_str(Address *address);

char[] get_address_id_str(Address *address);


/// Announce creation of a new Channel.
Address auth_send_announce(Author *author);

/// Subscribe a new subscriber.
void auth_receive_subscribe(Author * author, Address *address);

/// Create a new keyload for a list of subscribers.
MessageLinks auth_send_keyload(Author *author , Address *link_to, PskIds *psk_ids , PubKeyWrap[] ke_pks);

/// Create keyload for all subscribed subscribers.
MessageLinks auth_send_keyload_for_everyone(Author * author , Address *link_to);

// Our branching choice
u8 auth_get_branching_flag(Author * author);

/// Create a tagged packet.
MessageLinks auth_send_tagged_packet(Author * author , MessageLinks *link_to, char * public_payload , char *masked_payload );

/// Create a tagged packet.
MessageLinks auth_send_signed_packet(Author * author , MessageLinks *link_to, char * public_payload , char *masked_payload );

// Unwrap a tagged packet for an author
PayloadResponse auth_receive_tagged_packet(Author * author , Address *address) ;

// Unwrap a sequence message for an author
Address auth_receive_sequence(Author * author, Address *address);

Address get_msg_link(MessageLinks *message_links);

Address get_seq_link(MessageLinks *message_links);

Message get_transaction(Address *link_to);

MessageReturns auth_fetch_next_msgs(Author *author);
MsgReturn auth_receive_msg(Author *author, Address *link);
NextMsgId auth_gen_next_msg_ids(Author *author);

Subscriber sub_new(char seed[], char encoding[], size_t payload_length);
void sub_receive_announce(Subscriber *subscriber, Address *maddress);
Address sub_send_subscribe(Subscriber *subscriber, Address *announcement_link);

void sub_receive_keyload(Subscriber *subscriber, Address *address);

Address sub_receive_sequence(Subscriber *subscriber, Address *address);
Address sub_get_message_link(Subscriber *subscriber, Address *address);
PayloadResponse sub_receive_signed_packet(Subscriber *subscriber, Address *address);
PayloadResponse sub_receive_tagged_packet(Subscriber *subscriber, Address *address);

MessageReturns sub_fetch_next_msgs(Subscriber *subscriber);
MsgReturn sub_receive_msg(Subscriber *subscriber, Address *link);
NextMsgId sub_gen_next_msg_ids(Subcriber *subscriber);
NextMsgId sub_sync_state(Subscriber *subscriber);


u8 sub_get_branching_flag(Subscriber *subscriber);
u8 sub_is_registered(Subscriber *subscriber);
void sub_unregister(Subscriber *subscriber);

/*
void auth_store_state(Author * author, PubKey * pk, Address * link);

void auth_store_state_for_all(Author * author, Address * link, size_t
eq_num ) ;

SeqState auth_get_seq_state(Author * author, PubKey * pk);



Address auth_gen_msg_id(Author * author, Address * link, PubKey * pk, size_t seq) ;

*/
}

/// Sub section

