#include <stdbool.h>
#include <string.h>


typedef struct Author author_t;
extern author_t *auth_new(char seed[], char encoding[], size_t payload_length, bool multi_branching);

typedef struct AppInst appinst_t;
extern appinst_t *auth_channel_address(author_t *author);
extern char *get_appinst_str(appinst_t *appinst);

typedef struct MsgId msgid_t;
extern char *get_msgid_str(msgid_t *msgid);

typedef struct Address address_t;
extern char *get_address_inst_str(address_t *address);
extern char *get_address_id_str(address_t *address);

typedef struct Transport transport_t;
extern transport_t *init_transport();

typedef struct PskIds pskids_t;

typedef struct PubKey pubkey_t;

typedef struct PubKeyWrap pubkeywrap_t;

typedef struct Message message_t;
extern address_t *auth_announce(author_t *author);
extern address_t *auth_share_keyload(author_t *author, address_t *link_to, pskids_t *psk_ids, pubkeywrap_t ke_pks);
extern address_t *auth_share_keyload_for_everyone(author_t *author, address_t *link_to);

typedef struct SeqState seqstate_t;

typedef struct NextMsgId nextmsgid_t;

typedef struct Preparsed preparsed_t;