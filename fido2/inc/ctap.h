// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_H_
#define _CTAP_H_

#include "cbor.h"
#include <stdint.h>

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

/* MAKE_CREDENTIAL (0x01) */

// Commands
#define MC_Cmd_clientDataHash        0x01 // Data type: Byte String
#define MC_Cmd_rp                    0x02 // Data type: PublicKeyCredentialRpEntity
#define MC_Cmd_user                  0x03 // Data type: PublicKeyCredentialUserEntity
#define MC_Cmd_pubKeyCredParams      0x04 // Data type: Array of PublicKeyCredentialParameters
#define MC_Cmd_excludeList           0x05 // Data type: Array of PublicKeyCredentialDescriptor
#define MC_Cmd_extensions            0x06 // Data type: CBOR map of extension identifier authenticator extension input values
#define MC_Cmd_options               0x07 // Data type: Map of authenticator options
#define MC_Cmd_pinUvAuthParam        0x08 // Data type: Byte String
#define MC_Cmd_pinUvAuthProtocol     0x09 // Data type: Unsigned Integer
#define MC_Cmd_enterpriseAttestation 0x0A // Data type: Unsigned Integer

// Response structures
#define MC_Resp_fmt                 0x01 // Data type: String
#define MC_Resp_authData            0x02 // Data type: Byte String
#define MC_Resp_attStmt             0x03 // Data type: CBOR Map, the structure of which depends on the attestation statement format identifier
#define MC_Resp_epAtt               0x04 // Data type: Boolean
#define MC_Resp_largeBlobKey        0x05 // Data type: Byte string

//-----------------------------------------------------------------------------

/* GET_ASSERTION (0x02) */

// Commands
#define GA_Cmd_rpId              0x01 // Data type: String
#define GA_Cmd_clientDataHash    0x02 // Data type: Byte String
#define GA_Cmd_allowList         0x03 // Data type: Array of PublicKeyCredentialDescriptor
#define GA_Cmd_extensions        0x04 // Data type: CBOR map of extension identifier authenticator extension input values
#define GA_Cmd_options           0x05 // Data type: Map of authenticator options
#define GA_Cmd_pinUvAuthParam    0x06 // Data type: Byte String
#define GA_Cmd_pinUvAuthProtocol 0x07 // Data type: Unsigned Integer

// Response structures
#define GA_Resp_credential          0x01 // Data type: PublicKeyCredentialDescriptor
#define GA_Resp_authData            0x02 // Data type: Byte String
#define GA_Resp_signature           0x03 // Data type: Byte String
#define GA_Resp_user                0x04 // Data type: PublicKeyCredentialUserEntity
#define GA_Resp_numberOfCredentials 0x05 // Data type: Integer
#define GA_Resp_userSelected        0x06 // Data type: Boolean
#define GA_Resp_largeBlobKey        0x07 // Data type: Byte string

//-----------------------------------------------------------------------------

/* GET_INFO (0x04) */

// Response structures
#define GI_Resp_versions                         0x01 // Data type: Array of strings
#define GI_Resp_extensions                       0x02 // Data type: Array of strings
#define GI_Resp_aaguid                           0x03 // Data type: Byte String
#define GI_Resp_options                          0x04 // Data type: Map
#define GI_Resp_maxMsgSize                       0x05 // Data type: Unsigned Integer
#define GI_Resp_pinUvAuthProtocols               0x06 // Data type: Array of Unsigned Integers
#define GI_Resp_maxCredentialCountInList         0x07 // Data type: Unsigned Integer
#define GI_Resp_maxCredentialIdLength            0x08 // Data type: Unsigned Integer
#define GI_Resp_transports                       0x09 // Data type: Array of strings
#define GI_Resp_algorithms                       0x0A // Data type: Array of PublicKeyCredentialParameters
#define GI_Resp_maxSerializedLargeBlobArray      0x0B // Data type: Unsigned Integer
#define GI_Resp_forcePINChange                   0x0C // Data type: Boolean
#define GI_Resp_minPINLength                     0x0D // Data type: Unsigned Integer
#define GI_Resp_firmwareVersion                  0x0E // Data type: Unsigned Integer
#define GI_Resp_maxCredBlobLength                0x0F // Data type: Unsigned Integer
#define GI_Resp_maxRPIDsForSetMinPINLength       0x10 // Data type: Unsigned Integer
#define GI_Resp_preferredPlatformUvAttempts      0x11 // Data type: Unsigned Integer. (CBOR major type 0)
#define GI_Resp_uvModality                       0x12 // Data type: Unsigned Integer. (CBOR major type 0)
#define GI_Resp_certifications                   0x13 // Data type: Map
#define GI_Resp_remainingDiscoverableCredentials 0x14 // Data type: Unsigned Integer
#define GI_Resp_vendorPrototypeConfigCommands    0x15 // Data type: Array of Unsigned Integers

//-----------------------------------------------------------------------------

/* CLIENT_PIN (0x06) */

// Commands
#define CP_Cmd_pinUvAuthProtocol 0x01 // Data type: Unsigned Integer
#define CP_Cmd_subCommand        0x02 // Data type: Unsigned Integer
#define CP_Cmd_keyAgreement      0x03 // Data type: COSE_Key
#define CP_Cmd_pinUvAuthParam    0x04 // Data type: Byte String
#define CP_Cmd_newPinEnc         0x05 // Data type: Byte String
#define CP_Cmd_pinHashEnc        0x06 // Data type: Byte String
#define CP_Cmd_permissions       0x09 // Data type: Unsigned Integer
#define CP_Cmd_rpId              0x0A // Data type: String

// SubCommands
#define CP_SubCmd_getPINRetries                            0x01
#define CP_SubCmd_getKeyAgreement                          0x02
#define CP_SubCmd_setPIN                                   0x03
#define CP_SubCmd_changePIN                                0x04
#define CP_SubCmd_getPinToken                              0x05 // Superseded by getPinUvAuthTokenUsingUvWithPermissions or getPinUvAuthTokenUsingPinWithPermissions, thus for backwards compatibility only.
#define CP_SubCmd_getPinUvAuthTokenUsingUvWithPermissions  0x06
#define CP_SubCmd_getUVRetries                             0x07
#define CP_SubCmd_getPinUvAuthTokenUsingPinWithPermissions 0x09

// Response structures
#define CP_Resp_keyAgreement    0x01 // Data type: COSE_Key
#define CP_Resp_pinUvAuthToken  0x02 // Data type: Byte String
#define CP_Resp_pinRetries      0x03 // Data type: Unsigned Integer
#define CP_Resp_powerCycleState 0x04 // Data type: Boolean
#define CP_Resp_uvRetries       0x05 // Data type: Unsigned Integer

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

/* CREDENTIAL_MANAGEMENT (0x0A) */

// Commands
#define CM_Cmd_subCommand        0x01 // Data type: Unsigned Integer
#define CM_Cmd_subCommandParams  0x02 // Data type: CBOR Map
#define CM_Cmd_pinUvAuthProtocol 0x03 // Data type: Unsigned Integer
#define CM_Cmd_pinUvAuthParam    0x04 // Data type: Byte String

// SubCommands
#define CM_SubCmd_getCredsMetadata                      0x01
#define CM_SubCmd_enumerateRPsBegin                     0x02
#define CM_SubCmd_enumerateRPsGetNextRP                 0x03
#define CM_SubCmd_enumerateCredentialsBegin             0x04
#define CM_SubCmd_enumerateCredentialsGetNextCredential 0x05
#define CM_SubCmd_deleteCredential                      0x06

// SubCommandParams
#define CM_SubCmdParam_rpIDHash     0x01 // Data type: Byte String
#define CM_SubCmdParam_credentialID 0x02 // Data type: PublicKeyCredentialDescriptor
#define CM_SubCmdParam_user         0x03 // Data type: PublicKeyCredentialUserEntity

// Response structures
#define CM_Resp_existingResidentCredentialsCount             0x01 // Data type: Unsigned Integer
#define CM_Resp_maxPossibleRemainingResidentCredentialsCount 0x02 // Data type: Unsigned Integer
#define CM_Resp_rp                                           0x03 // Data type: PublicKeyCredentialRpEntity
#define CM_Resp_rpIDHash                                     0x04 // Data type: Byte String
#define CM_Resp_totalRPs                                     0x05 // Data type: Unsigned Integer
#define CM_Resp_user                                         0x06 // Data type: PublicKeyCredentialUserEntity
#define CM_Resp_credentialID                                 0x07 // Data type: PublicKeyCredentialDescriptor
#define CM_Resp_publicKey                                    0x08 // Data type: COSE_Key
#define CM_Resp_totalCredentials                             0x09 // Data type: Unsigned Integer
#define CM_Resp_credProtect                                  0x0A // Data type: Unsigned Integer
#define CM_Resp_largeBlobKey                                 0x0B // Data type: Byte string

//-----------------------------------------------------------------------------

#define EXT_HMAC_SECRET_COSE_KEY  0x01
#define EXT_HMAC_SECRET_SALT_ENC  0x02
#define EXT_HMAC_SECRET_SALT_AUTH 0x03

#define EXT_HMAC_SECRET_REQUESTED 0x01
#define EXT_HMAC_SECRET_PARSED    0x02

#define EXT_CRED_PROTECT_INVALID              0x00
#define EXT_CRED_PROTECT_OPTIONAL             0x01
#define EXT_CRED_PROTECT_OPTIONAL_WITH_CREDID 0x02
#define EXT_CRED_PROTECT_REQUIRED             0x03

#define CREDID_ALG_ES256 0x0
#define CREDID_ALG_EDDSA 0x1

#define PARAM_clientDataHash   (1 << 0)
#define PARAM_rp               (1 << 1)
#define PARAM_user             (1 << 2)
#define PARAM_pubKeyCredParams (1 << 3)
#define PARAM_excludeList      (1 << 4)
#define PARAM_extensions       (1 << 5)
#define PARAM_options          (1 << 6)
#define PARAM_pinAuth          (1 << 7)
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

#define PUB_KEY_CRED_PUB_KEY 0x01
#define PUB_KEY_CRED_CTAP1   0x41
#define PUB_KEY_CRED_CUSTOM  0x42
#define PUB_KEY_CRED_UNKNOWN 0x3F

#define CREDENTIAL_IS_SUPPORTED  1
#define CREDENTIAL_NOT_SUPPORTED 0

#define ALLOW_LIST_MAX_SIZE 20

#define NEW_PIN_ENC_MAX_SIZE 256 // Includes NULL terminator
#define NEW_PIN_ENC_MIN_SIZE 64
#define NEW_PIN_MAX_SIZE     64
#define NEW_PIN_MIN_SIZE     4

#define CTAP_RESPONSE_BUFFER_SIZE 4096

#define PIN_LOCKOUT_ATTEMPTS 8 // Number of attempts total
#define PIN_BOOT_ATTEMPTS    3 // Number of attempts per boot

#define CTAP2_UP_DELAY_MS 29000
// clang-format off

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
	uint8_t type;
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
	struct {
		uint8_t x[32];
		uint8_t y[32];
	} pubkey;

	int kty;
	int crv;
} COSE_key;

typedef struct {
	uint8_t saltLen;
	uint8_t saltEnc[64];
	uint8_t saltAuth[32];
	COSE_key keyAgreement;
	struct Credential *credential;
} CTAP_hmac_secret;

typedef struct {
	uint8_t hmac_secret_present;
	CTAP_hmac_secret hmac_secret;
	uint8_t cred_protect;
} CTAP_extensions;

typedef struct {
	CTAP_userEntity user;
	uint8_t publicKeyCredentialType;
	int32_t COSEAlgorithmIdentifier;
	uint8_t rk;
} CTAP_credInfo;

typedef struct {
	uint32_t paramsParsed;
	uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
	struct rpId rp;

	CTAP_credInfo credInfo;

	CborValue excludeList;
	size_t excludeListSize;

	uint8_t uv;
	uint8_t up;

	uint8_t pinAuth[16];
	uint8_t pinAuthPresent;
	// pinAuthEmpty is true iff an empty bytestring was provided as pinAuth.
	// This is exclusive with |pinAuthPresent|. It exists because an empty
	// pinAuth is a special signal to block for touch. See
	// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#using-pinToken-in-authenticatorMakeCredential
	uint8_t pinAuthEmpty;
	int pinProtocol;
	CTAP_extensions extensions;

} CTAP_makeCredential;

typedef struct {
	uint32_t paramsParsed;
	uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
	uint8_t clientDataHashPresent;

	struct rpId rp;

	int credLen;

	uint8_t rk;
	uint8_t uv;
	uint8_t up;

	uint8_t pinAuth[16];
	uint8_t pinAuthPresent;
	// pinAuthEmpty is true iff an empty bytestring was provided as pinAuth.
	// This is exclusive with |pinAuthPresent|. It exists because an empty
	// pinAuth is a special signal to block for touch. See
	// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#using-pinToken-in-authenticatorGetAssertion
	uint8_t pinAuthEmpty;
	int pinProtocol;

	CTAP_credentialDescriptor *creds;
	uint8_t allowListPresent;

	CTAP_extensions extensions;

} CTAP_getAssertion;

typedef struct {
	int cmd;
	struct {
		uint8_t rpIdHash[32];
		CTAP_credentialDescriptor credentialDescriptor;
	} subCommandParams;

	struct {
		uint8_t cmd;
		uint8_t
		    subCommandParamsCborCopy[sizeof(CTAP_credentialDescriptor) +
					     16];
	} hashed;
	uint32_t subCommandParamsCborSize;

	uint8_t pinAuth[16];
	uint8_t pinAuthPresent;
	int pinProtocol;
} CTAP_credMgmt;

typedef struct {
	int pinProtocol;
	int subCommand;
	COSE_key keyAgreement;
	uint8_t keyAgreementPresent;
	uint8_t pinAuth[16];
	uint8_t pinAuthPresent;
	uint8_t newPinEnc[NEW_PIN_ENC_MAX_SIZE];
	int newPinEncSize;
	uint8_t pinHashEnc[16];
	uint8_t pinHashEncPresent;
	_Bool getKeyAgreement;
	_Bool getRetries;
} CTAP_clientPin;

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

void ctap_response_init(CTAP_RESPONSE *resp);

uint8_t ctap_request(uint8_t *pkt_raw, int length, CTAP_RESPONSE *resp);

// Encodes R,S signature to 2 der sequence of two integers.  Sigder must be at
// least 72 bytes.
// @return length of der signature
int ctap_encode_der_sig(uint8_t const *const in_sigbuf,
			uint8_t *const out_sigder);

// Run ctap related power-up procedures (init pinToken, generate shared secret)
void ctap_init();

// Resets state between different accesses of different applications
void ctap_reset_state();

uint8_t ctap_add_pin_if_verified(uint8_t *pinTokenEnc, uint8_t *platform_pubkey,
				 uint8_t *pinHashEnc);
uint8_t ctap_update_pin_if_verified(uint8_t *pinEnc, int len,
				    uint8_t *platform_pubkey, uint8_t *pinAuth,
				    uint8_t *pinHashEnc);

void ctap_update_pin(uint8_t *pin, int len);
uint8_t ctap_decrement_pin_attempts();
int8_t ctap_leftover_pin_attempts();
void ctap_reset_pin_attempts();
uint8_t ctap_is_pin_set();
uint8_t ctap_pin_matches(uint8_t *pin, int len);
void ctap_reset();
int8_t ctap_device_locked();
int8_t ctap_device_boot_locked();

#define PIN_TOKEN_SIZE 16
extern uint8_t PIN_TOKEN[PIN_TOKEN_SIZE];
extern uint8_t KEY_AGREEMENT_PUB[64];

void lock_device_permanently();

#endif
