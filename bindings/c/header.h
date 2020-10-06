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

///////////
/// Author
///////////

/// Generate a new Author Instance
Author auth_new(char[] seed, char[] encoding, size_t payload_length, bool multi_branching);

/// Channel app instance.
AppInst auth_channel_address(Author *author);

/// Announce creation of a new Channel.
Address auth_send_announce(Author *author);

/// Subscribe a new subscriber.
void auth_receive_subscribe(Author * author, Address *address);

/// Create a new keyload for a list of subscribers.
MessageLinks auth_send_keyload(Author *author , Address *link_to, PskIds *psk_ids , PubKeyWrap[] ke_pks);

/// Create keyload for all subscribed subscribers.
MessageLinks auth_send_keyload_for_everyone(Author * author , Address *link_to);

/// Our branching choice
u8 auth_get_branching_flag(Author * author);

/// Create a tagged packet.
MessageLinks auth_send_tagged_packet(Author * author , MessageLinks *link_to, char * public_payload , char *masked_payload );

/// Create a tagged packet.
MessageLinks auth_send_signed_packet(Author * author , MessageLinks *link_to, char * public_payload , char *masked_payload );

/// Unwrap a tagged packet for an author
PayloadResponse auth_receive_tagged_packet(Author * author , Address *address) ;

/// Unwrap a tagged packet for an author
PayloadResponse auth_receive_signed_packet(Author * author , Address *address) ;

/// Unwrap a sequence message for an author
Address auth_receive_sequence(Author * author, Address *address);

/// Fetch next message from each sender if available
MessageReturns auth_fetch_next_msgs(Author *author);

/// Sync State of author
MessageReturns auth_sync_state(Author *author);

/// Handle message link regardless of type
MsgReturn auth_receive_msg(Author *author, Address *link);

/// Generate msgids for next expected messages
NextMsgId auth_gen_next_msg_ids(Author *author);



///////////////
/// Subscriber
///////////////

/// Generate a new Author Instance
Subscriber sub_new(char seed[], char encoding[], size_t payload_length);

/// Get Branching State
u8 sub_get_branching_flag(Subscriber *subscriber);

/// Check if subscriber is registered
u8 sub_is_registered(Subscriber *subscriber);

/// Unregister subscriber instance
void sub_unregister(Subscriber *subscriber);

/// Unwrap Announcement Message
void sub_receive_announce(Subscriber *subscriber, Address *maddress);

/// Subscribe to channel
Address sub_send_subscribe(Subscriber *subscriber, Address *announcement_link);

/// Unwrap Keyload Message
void sub_receive_keyload(Subscriber *subscriber, Address *address);

/// Unwrap Sequence Message
Address sub_receive_sequence(Subscriber *subscriber, Address *address);

/// Create a tagged packet.
MessageLinks sub_send_tagged_packet(Subscriber *subscriber , MessageLinks *link_to, char * public_payload , char *masked_payload );

/// Create a tagged packet.
MessageLinks sub_send_signed_packet(Subscriber *subscriber , MessageLinks *link_to, char * public_payload , char *masked_payload );

/// Unwrap Signed Packet Message
PayloadResponse sub_receive_signed_packet(Subscriber *subscriber, Address *address);

/// Unwrap Tagged Packet Message
PayloadResponse sub_receive_tagged_packet(Subscriber *subscriber, Address *address);

/// Fetch next message from each sender if available
MessageReturns sub_fetch_next_msgs(Subscriber *subscriber);

/// Sync State of subscriber
MessageReturns sub_sync_state(Subscriber *subscriber);

/// Handle message link regardless of type
MsgReturn sub_receive_msg(Subscriber *subscriber, Address *link);

/// Generate msgids for next expected messages
NextMsgId sub_gen_next_msg_ids(Subcriber *subscriber);

///////////
/// Utils
///////////
Address get_msg_link(MessageLinks *message_links);
Address get_seq_link(MessageLinks *message_links);

char[] get_appinst_str(AppInst *appinst);
char[] get_msgid_str(MsgId *msgid);
char[] get_address_inst_str(Address *address);
char[] get_address_id_str(Address *address);

/// Get Payloads from a tagged or signed packet return
PayloadResponse get_payload(MsgReturn *message_return);
PayloadResponse get_indexed_payload(MessageReturns *message_returns, int index);
}
