#ifndef STREAMS_HEADER_H
#define STREAMS_HEADER_H
#endif //STREAMS_HEADER_H


struct AppInst;

struct MsgId;

struct Address;

struct Author;

struct Message;

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

/// Create a new keyload for a list of subscribers.
Address[2] auth_share_keyload(Author *author , Address *link_to, PskIds *psk_ids , PubKeyWrap[] ke_pks);

/// Create keyload for all subscribed subscribers.
Address[2] auth_share_keyload_for_everyone(Author * author , Address *link_to);
/*
void auth_store_state(Author * author, PubKey * pk, Address * link);

void auth_store_state_for_all(Author * author, Address * link, size_t
eq_num ) ;

SeqState auth_get_seq_state(Author * author, PubKey * pk);

/// Create a signed packet.
Message [ 2 ] auth_sign_packet(Author * author , Address *link_to, Bytes * public_payload , Bytes *masked_payload ) ;

/// Create a tagged packet.
Message [ 2 ] auth_tag_packet(Author * author , Address *link_to, Bytes * public_payload , Bytes *masked_payload ) ;

/// Unwrap tagged packet.
Bytes [ 2 ] auth_unwrap_tagged_packet(Author * author , Preparsed *preparsed ) ;

/// Subscribe a new subscriber.
void auth_unwrap_subscribe(Author * author, Preparsed * preparsed);

Address auth_unwrap_sequence(Author * author, Preparsed * preparsed);

char auth_get_branching_flag(Author * author);

Address auth_gen_msg_id(Author * author, Address * link, PubKey * pk, size_t seq) ;

NextMsgId [ ] auth_gen_next_msg_ids(Author *author , bool branching) ;
*/
}

/// Sub section

