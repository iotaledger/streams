#ifndef STREAMS_HEADER_H
#define STREAMS_HEADER_H
#endif //STREAMS_HEADER_H


struct AppInst;

struct MsgId;

struct Address;

struct Author;

struct Message;

struct MessageLinks;

struct PskIds;

struct PubKey;

struct PubKeyWrap;

struct SeqState; // (Address, usize[size_t])

struct NextMsgId; // vec(Pubkey, (address, usize))

struct Preparsed;

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
Address auth_announce(Author *author);

/// Subscribe a new subscriber.
void auth_unwrap_subscribe(Author * author, Message * preparsed);

/// Create a new keyload for a list of subscribers.
MessageLinks auth_share_keyload(Author *author , Address *link_to, PskIds *psk_ids , PubKeyWrap[] ke_pks);

/// Create keyload for all subscribed subscribers.
MessageLinks auth_share_keyload_for_everyone(Author * author , Address *link_to);

// Our branching choice
u8 auth_get_branching_flag(Author * author);

/// Create a tagged packet.
MessageLinks auth_tag_packet(Author * author , MessageLinks *link_to, char * public_payload , char *masked_payload );

/// Create a tagged packet.
MessageLinks auth_sign_packet(Author * author , MessageLinks *link_to, char * public_payload , char *masked_payload );

// Unwrap a tagged packet for an author
PayloadResponse auth_unwrap_tagged_packet(Author * author , Message *message) ;

// Unwrap a sequence message for an author
Address auth_unwrap_sequence(Author * author, Message *message);

Address get_msg_link(MessageLinks *message_links);

Address get_seq_link(MessageLinks *message_links);

Message get_transaction(Address *link_to);

Message auth_fetch_next_transaction(Author *author);

Subscriber sub_new(char seed[], char encoding[], size_t payload_length);
void sub_unwrap_announce(Subscriber *subscriber, Message *message);
Address sub_subscribe(Subscriber *subscriber, Address *announcement_link);

void sub_unwrap_keyload(Subscriber *subscriber, Message *message);

Address sub_unwrap_sequence(Subscriber *subscriber, , Message *message);
Address sub_get_message_link(Subscriber *subscriber, Address *address);
PayloadResponse sub_unwrap_signed_packet(Subscriber *subscriber, Message *message);
PayloadResponse sub_unwrap_tagged_packet(Subscriber *subscriber, Message *message);

u8 sub_get_branching_flag(Subscriber * author);

/*
void auth_store_state(Author * author, PubKey * pk, Address * link);

void auth_store_state_for_all(Author * author, Address * link, size_t
eq_num ) ;

SeqState auth_get_seq_state(Author * author, PubKey * pk);



Address auth_gen_msg_id(Author * author, Address * link, PubKey * pk, size_t seq) ;

NextMsgId [ ] auth_gen_next_msg_ids(Author *author , bool branching) ;
*/
}

/// Sub section

