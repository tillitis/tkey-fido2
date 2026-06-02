// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_H_
#define _CTAP_H_

#include <stddef.h>
#include <stdint.h>

#include "cbor.h"
#include "cose_key.h"
#include "ctap_extensions.h"

// Authenticator API commands
// clang-format off
#define CTAP_MAKE_CREDENTIAL           0x01
#define CTAP_GET_ASSERTION             0x02
//#define CTAP_CANCEL                  0x03 // Deprecated
#define CTAP_GET_INFO                  0x04
#define CTAP_CLIENT_PIN                0x06
#define CTAP_RESET                     0x07
#define CTAP_GET_NEXT_ASSERTION        0x08
#define CTAP_BIO_ENROLLMENT            0x09
#define CTAP_CREDENTIAL_MANAGEMENT     0x0A
#define CTAP_SELECTION                 0x0B
#define CTAP_LARGE_BLOBS               0x0C
#define CTAP_CONFIG                    0x0D
#define CTAP_VENDOR_FIRST              0x40
#define CTAP_BIO_ENROLLMENT_PRE        0x40 // For FIDO_2_1_PRE backwards compatibility
#define CTAP_CREDENTIAL_MANAGEMENT_PRE 0x41 // For FIDO_2_1_PRE backwards compatibility
#define CTAP_VENDOR_LAST               0xBF

//-----------------------------------------------------------------------------

/* BIO_ENROLLMENT (0x09) */

// Commands
#define BE_Cmd_modality          0x01 // Data type: Unsigned Integer
#define BE_Cmd_subCommand        0x02 // Data type: Unsigned Integer
#define BE_Cmd_subCommandParams  0x03 // Data type: CBOR Map
#define BE_Cmd_pinUvAuthProtocol 0x04 // Data type: Unsigned Integer
#define BE_Cmd_pinUvAuthParam    0x05 // Data type: Byte String
#define BE_Cmd_getModality       0x06 // Data type: Boolean

// SubCommands
#define BE_SubCmd_enrollBegin              0x01
#define BE_SubCmd_enrollCaptureNextSample  0x02
#define BE_SubCmd_cancelCurrentEnrollment  0x03
#define BE_SubCmd_enumerateEnrollments     0x04
#define BE_SubCmd_setFriendlyName          0x05
#define BE_SubCmd_removeEnrollment         0x06
#define BE_SubCmd_getFingerprintSensorInfo 0x07

// SubCommandParams
#define BE_SubCmdParam_templateId           0x01 // Data type: Byte String
#define BE_SubCmdParam_templateFriendlyName 0x02 // Data type: String
#define BE_SubCmdParam_timeoutMilliseconds  0x03 // Data type: Unsigned Integer

// Modality
#define BE_Modality_fingerprint             0x01

// TemplateInfo
#define BE_TemplateInfo_templateId           0x01 // Data type: Byte String
#define BE_TemplateInfo_templateFriendlyName 0x02 // Data type: String

// Response structures
#define BE_Resp_modality                           0x01 // Data type: Unsigned Integer
#define BE_Resp_fingerprintKind                    0x02 // Data type: Unsigned Integer
#define BE_Resp_maxCaptureSamplesRequiredForEnroll 0x03 // Data type: Unsigned Integer
#define BE_Resp_templateId                         0x04 // Data type: Byte String
#define BE_Resp_lastEnrollSampleStatus             0x05 // Data type: Unsigned Integer
#define BE_Resp_remainingSamples                   0x06 // Data type: Unsigned Integer
#define BE_Resp_templateInfos                      0x07 // Data type: CBOR ARRAY
#define BE_Resp_maxTemplateFriendlyName            0x08 // Data type: Unsigned Integer

//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------

#define CREDID_ALG_ES256 0x0
#define CREDID_ALG_EDDSA 0x1

#define PARAM_clientDataHash   (1 << 0)
#define PARAM_rp               (1 << 1)
#define PARAM_user             (1 << 2)
#define PARAM_pubKeyCredParams (1 << 3)
#define PARAM_excludeList      (1 << 4)
#define PARAM_extensions       (1 << 5)
#define PARAM_options          (1 << 6)
#define PARAM_pinUvAuthParam   (1 << 7)
#define PARAM_pinProtocol      (1 << 8)
#define PARAM_rpId             (1 << 9)
#define PARAM_allowList        (1 << 10)

#define MC_requiredMask (0x0f)

#define CLIENT_DATA_HASH_SIZE 32  // SHA256 hash
#define DOMAIN_NAME_MAX_SIZE  253
#define RP_NAME_LIMIT         32  // Application limit, name parameter isn't needed.
#define USER_ID_MAX_SIZE      64
#define USER_NAME_LIMIT       65  // Must be minimum of 64 bytes but can be more.
#define DISPLAY_NAME_LIMIT    32  // Must be minimum of 64 bytes but can be more.
#define CTAP_MAX_MESSAGE_SIZE 1200

#define CREDENTIAL_TAG_SIZE               16
#define CREDENTIAL_NONCE_SIZE             16
#define CREDENTIAL_METADATA_SIZE          4
#define CREDENTIAL_META_CRED_PROTECT_BYTE 3
#define CREDENTIAL_META_ALG_BYTE          2
#define CREDENTIAL_META_FLAGS_BYTE        0
#define CREDENTIAL_META_IS_RK_BITMASK     1

#define CREDENTIAL_COUNTER_SIZE 4
#define CREDENTIAL_ENC_SIZE     176 // Pad to multiple of 16 bytes

#define CREDENTIAL_RP_ID_SIZE 32

#define PUB_KEY_CRED_CTAP1   0x41
#define PUB_KEY_CRED_UNKNOWN 0x3F

#define CREDENTIAL_IS_SUPPORTED  1
#define CREDENTIAL_NOT_SUPPORTED 0

#define ALLOW_LIST_MAX_SIZE 20

#define CTAP_RESPONSE_BUFFER_SIZE 4096

#define CTAP2_UP_DELAY_MS 29000
// clang-format on

typedef struct {
	uint8_t id[USER_ID_MAX_SIZE];
	uint8_t id_size;
	uint8_t name[USER_NAME_LIMIT];
	uint8_t displayName[DISPLAY_NAME_LIMIT];
} __attribute__((packed)) CTAP_userEntity;

typedef struct {
	uint8_t tag[CREDENTIAL_TAG_SIZE];
	uint8_t rp_id_lookup[CREDENTIAL_TAG_SIZE]; //  = hmac(key, rp_id_hash)
	uint8_t nonce[CREDENTIAL_NONCE_SIZE];
	uint8_t protected_metadata[CREDENTIAL_METADATA_SIZE];
	uint32_t count;
} __attribute__((packed)) CredentialId;

struct __attribute__((packed)) Credential {
	CredentialId id;
	CTAP_userEntity user;
};

typedef struct {
	uint8_t rp_id_hash[32];
	uint8_t rp_id[CREDENTIAL_RP_ID_SIZE];
	uint8_t rp_id_size;
} __attribute__((packed)) rpEntity;

typedef struct {
	CredentialId id;
	CTAP_userEntity user;

	// Data for the credential management api
	rpEntity rp;
	uint8_t user_id_lookup[CREDENTIAL_TAG_SIZE]; // hmac(key, id)
	uint8_t rk_nonce[CREDENTIAL_NONCE_SIZE];
	uint8_t rk_tag[CREDENTIAL_TAG_SIZE];
} __attribute__((packed)) CTAP_residentKey;

#define RK_HMAC_SIZE                                                           \
	(sizeof(CTAP_userEntity) + sizeof(rpEntity) + CREDENTIAL_TAG_SIZE +    \
	 CREDENTIAL_NONCE_SIZE)

typedef struct {
	PublicKeyCredentialType type;
	struct Credential credential;
} CTAP_credentialDescriptor;

typedef struct {
	uint8_t aaguid[16];
	uint8_t credLenH;
	uint8_t credLenL;
	CredentialId id;
} __attribute__((packed)) CTAP_attestHeader;

typedef struct {
	uint8_t rpIdHash[32];
	uint8_t flags;
	uint32_t signCount;
} __attribute__((packed)) CTAP_authDataHeader;

typedef struct {
	CTAP_authDataHeader head;
	CTAP_attestHeader attest;
} __attribute__((packed)) CTAP_authData;

typedef struct {
	uint8_t data[CTAP_RESPONSE_BUFFER_SIZE];
	uint16_t data_size;
	uint16_t length;
} CTAP_RESPONSE;

struct rpId {
	uint8_t id[DOMAIN_NAME_MAX_SIZE + 1]; // extra for NULL termination
	size_t size;
	uint8_t name[RP_NAME_LIMIT];
};

typedef struct {
	CTAP_userEntity user;
	PublicKeyCredentialType publicKeyCredentialType;
	COSEAlgorithmIdentifier coseAlgorithmIdentifier;
	uint8_t rk;
} CTAP_credInfo;

struct _getAssertionState {
	// Room for both authData struct and extensions
	struct {
		CTAP_authDataHeader authData;
		uint8_t extensions[80];
	} __attribute__((packed)) buf;
	CTAP_extensions extensions;
	uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
	CTAP_credentialDescriptor creds[ALLOW_LIST_MAX_SIZE];
	uint8_t lastcmd;
	uint32_t count;
	uint32_t index;
	uint32_t time;
	uint8_t user_verified;
	uint8_t customCredId[256];
	uint8_t customCredIdSize;
};

CtapStatus ctap2_user_presence_test(void);
uint32_t ctap_auth_data_update_count(CTAP_authDataHeader *authData);
CtapStatus ctap_cbor_encode_credential_descriptor(CborEncoder *map,
						  struct Credential *cred,
						  PublicKeyCredentialType type);
CtapStatus ctap_cbor_encode_user_entity(CborEncoder *map, CTAP_userEntity *user,
					int is_verified);
uint8_t ctap_check_credential_metadata(CredentialId *credential,
				       uint8_t is_verified,
				       uint8_t is_from_credid_list,
				       uint8_t *is_rk);

void ctap_compute_mac(const void *data, size_t data_len, uint8_t *mac,
		      size_t mac_len);
int ctap_credential_belongs_to_rp(uint8_t *rp_id_lookup, uint8_t *rp_id_hash,
				  CTAP_credentialDescriptor *desc);
void ctap_decrement_rk_store(void);
void ctap_derive_rp_id_info(const uint8_t *rp_id, size_t size,
			    uint8_t *rp_id_hash, uint8_t *rp_id_lookup);
int ctap_encode_der_sig(uint8_t const *const in_sigbuf,
			uint8_t *const out_sigder);
void ctap_flush_state(void);
size_t ctap_get_credential_id_size(int type);
void ctap_increment_rk_store(void);
void ctap_init(void);
CtapStatus ctap_make_auth_data(struct rpId *rp, uint8_t *rp_id_hash,
			       uint8_t *rp_id_lookup, CborEncoder *map,
			       uint8_t *auth_data_buf, uint32_t *len,
			       CTAP_credInfo *credInfo,
			       CTAP_extensions *extensions);
void ctap_make_auth_tag(uint8_t *rp_id_lookup, uint8_t *nonce,
			uint8_t *metadata, uint32_t count, uint8_t *tag);
CtapStatus ctap_request(uint8_t *pkt_raw, size_t length, CTAP_RESPONSE *resp);
void ctap_response_init(CTAP_RESPONSE *resp);
int32_t ctap_restore_metadata_cose_alg(CredentialId *credential);
int ctap_sign_data(uint8_t *data, int datalen, uint8_t *clientDataHash,
		   uint8_t *hashbuf, uint8_t *sigbuf, uint8_t *sigder,
		   int32_t alg);
void ctap_state_init(void);
int ctap_verify_mac(const uint8_t *mac, const void *data, size_t data_len);
int ctap_verify_rk_exists(const CredentialId *input_cred);
void ctap_xcrypt_buf(const uint8_t *iv, const void *in, void *out,
		     uint8_t length);

#endif
