// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "assert.h"
#include "cbor.h"
#include "cose_key.h"
#include "crypto.h"
#include "ctap.h"
#include "ctap_client_pin.h"
#include "ctap_errors.h"
#include "ctap_parse.h"
#include "device.h"
#include "log.h"
#include "state.h"
#include "tkey/lib.h"
#include "uECC.h"

typedef struct {
	uint8_t priv_key[32];
	uint8_t pub_key[64];
	bool pub_key_valid;
} key_agreement_t;

#define TOKEN_MAX_USAGE_PERIOD_MS (10 * 60 * 1000) // 10 minutes
#define TOKEN_MAX_USER_PRESENT_MS (30 * 1000)	   // 30 seconds

typedef struct {
	uint8_t permissions_rp_id_hash[32];
	bool permissions_rp_id_present;
	uint8_t permissions;
	uint32_t usage_timer_start_ms;
	uint32_t usage_timer_last_used_ms;
	bool in_use;
	bool user_verified;
	bool user_present;
} pinUvAuthToken_state_t;

typedef struct {
	key_agreement_t key_agreement;
	uint8_t token[PINUVAUTHTOKEN_SIZE];
	pinUvAuthToken_state_t state;
} pinUvAuthToken_t;

static pinUvAuthToken_t pinUvAuthToken_p1 = {0x00};
static pinUvAuthToken_t pinUvAuthToken_p2 = {0x00};

int8_t PIN_BOOT_ATTEMPTS_LEFT = PIN_BOOT_ATTEMPTS;

extern AuthenticatorState STATE;

static CtapStatus
add_enc_pinUvAuthToken(uint8_t *pinTokenEnc, uint8_t *platform_pubkey,
		       uint8_t *pinHashEnc, uint8_t pinProtocol,
		       uint8_t permissions, uint8_t *rp_id, size_t rp_id_size);
static void associate_permissions_rp_id(uint8_t *rp_id, size_t rp_id_size,
					uint8_t pin_protocol);
static size_t auth_param_size(int proto);
static uint8_t decrement_pin_attempts(void);
static void decrypt(uint8_t *buf, uint32_t len, const uint8_t *enc_key,
		    uint8_t pin_protocol);
static int ecdh(uint8_t *platform_pubkey, uint8_t pin_protocol,
		uint8_t *shared_secret_enc_key, uint8_t *shared_secret_mac_key);
static int encrypt_pinUvAuthToken(uint8_t *out, int *out_len,
				  const uint8_t *enc_key, uint8_t pin_protocol);
static pinUvAuthToken_t *get_pin_protocol_state(uint8_t pin_protocol);
static void kdf(const uint8_t *ikm, int pin_protocol,
		uint8_t *shared_secret_enc_key, uint8_t *shared_secret_mac_key);
static uint8_t leftover_pin_attempts(void);
static void lock_device_permanently(void);
static CtapStatus parse_client_pin_request(CTAP_clientPin *CP, uint8_t *request,
					   size_t length);
static void regenerate_key_agreement(uint8_t pin_protocol);
static int reset_pinUvAuthToken(uint8_t pin_protocol);
static void reset_pin_attempts(void);
static size_t trailing_zeros(uint8_t *buf, size_t indx);
static void update_pin(uint8_t *pin, size_t len);
static CtapStatus update_pin_if_verified(uint8_t *newPinEnc, uint8_t len,
					 uint8_t *platform_pubkey,
					 uint8_t *pinUvAuthParam,
					 uint8_t *pinHashEnc,
					 uint8_t pinProtocol);
static int verify_against_stored_pin(uint8_t *pinHashEnc);
/* pinUvAuthToken State Maintenance Functions */
static void begin_using_pinUvAuthToken(bool user_is_preset,
				       uint8_t pin_protocol,
				       uint8_t permissions);
bool get_user_present(uint8_t pin_protocol);
static void pinUvAuthToken_usage_time_observer(uint8_t pin_protocol);
static void stop_using_pinUvAuthToken(uint8_t pin_protocol);

/* -------------------------------------------------------------------------
 * Public entry point
 * ---------------------------------------------------------------------- */
CtapStatus ctap_client_pin(CborEncoder *encoder, uint8_t *request,
			   size_t length)
{
	CTAP_clientPin CP;
	CborEncoder map;
	uint8_t pinTokenEnc[CP_IV_SIZE + PINUVAUTHTOKEN_SIZE];
	size_t pinTokenEncLen = 0;
	CborError cbor_ret;
	CtapStatus ctap_ret;

	ctap_ret = parse_client_pin_request(&CP, request, length);
	if (ctap_ret.value != CTAP2_OK) {
		printf2(TAG_ERR, "Error, parse_client_pin_request() failed\n");
		return ctap_ret;
	}

	// Validate pin protocol except for getPINRetries which is the only
	// exception
	if (CP.subCommand != CP_SubCmd_getPINRetries) {
		if (CP.pinProtocol == 0) {
			return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
		}

		if (CP.pinProtocol != 1 && CP.pinProtocol != 2) {
			return (CtapStatus){CTAP1_ERR_INVALID_PARAMETER};
		}
	}

	// Split into two switch cases:
	// 1. Sub commands that don't check for lock out
	// 2. Sub commands that do
	//
	// Switch 1 has to return in each case, so we can catch invalid
	// subcommands in switch two.

	switch (CP.subCommand) {
	case CP_SubCmd_getPINRetries:
		printf1(TAG_CP, "CP_SubCmd_getPINRetries\n");

		cbor_ret = cbor_encoder_create_map(encoder, &map, 2);
		cbor_check_ret(cbor_ret);

		cbor_ret = cbor_encode_int(&map, CP_Resp_pinRetries);
		cbor_check_ret(cbor_ret);
		cbor_ret = cbor_encode_uint(&map, leftover_pin_attempts());
		cbor_check_ret(cbor_ret);

		cbor_ret = cbor_encode_int(&map, CP_Resp_powerCycleState);
		cbor_check_ret(cbor_ret);
		cbor_ret = cbor_encode_boolean(
		    &map, ctap_client_pin_is_boot_locked() &&
			      !ctap_client_pin_is_locked());
		cbor_check_ret(cbor_ret);

		cbor_ret = cbor_encoder_close_container(encoder, &map);
		cbor_check_ret(cbor_ret);

		// Has to return here, or will get stuck in next switch.
		return (CtapStatus){CTAP2_OK};
		break;

	case CP_SubCmd_getKeyAgreement:
		printf1(TAG_CP, "CP_SubCmd_getKeyAgreement\n");

		// Already checked for missing parameter and pin protocol
		pinUvAuthToken_t *pinUvAuthToken =
		    get_pin_protocol_state(CP.pinProtocol);

		cbor_ret = cbor_encoder_create_map(encoder, &map, 1);
		cbor_check_ret(cbor_ret);

		cbor_ret = cbor_encode_int(&map, CP_Resp_keyAgreement);
		cbor_check_ret(cbor_ret);

		// Check if we have already calculated the public key
		if (!pinUvAuthToken->key_agreement.pub_key_valid) {

			crypto_ecc256_compute_public_key(
			    pinUvAuthToken->key_agreement.priv_key,
			    pinUvAuthToken->key_agreement.pub_key);

			pinUvAuthToken->key_agreement.pub_key_valid = true;
		}

		/* cose_key_add is equivialent with getPyblicKey() and CBOR
		 * encoding the result */
		ctap_ret =
		    cose_key_add(&map, pinUvAuthToken->key_agreement.pub_key,
				 pinUvAuthToken->key_agreement.pub_key + 32,
				 COSE_ALG_ECDH_ES_HKDF_256);
		ctap_check_retr(ctap_ret);

		cbor_ret = cbor_encoder_close_container(encoder, &map);
		cbor_check_ret(cbor_ret);

		// Has to return here, or will get stuck in next switch.
		return (CtapStatus){CTAP2_OK};
		break;

	case CP_SubCmd_setPIN:
		printf1(TAG_CP, "CP_SubCmd_setPIN\n");

		if (!CP.newPinEncSize || !CP.pinUvAuthParam_present ||
		    !CP.keyAgreementPresent) {
			return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
		}

		if (ctap_client_pin_is_set()) {
			return (CtapStatus){CTAP2_ERR_PIN_AUTH_INVALID};
		}

		ctap_ret = update_pin_if_verified(
		    CP.newPinEnc, CP.newPinEncSize,
		    (uint8_t *)&CP.keyAgreement.pubkey, CP.pinUvAuthParam, NULL,
		    CP.pinProtocol);
		ctap_check_retr(ctap_ret);

		// Has to return here, or will get stuck in next switch.
		return (CtapStatus){CTAP2_OK};
		break;

	default:
		// Do nothing
		break;
	}

	// Sub commands below require unlock
	if (ctap_client_pin_is_locked()) {
		return (CtapStatus){CTAP2_ERR_PIN_BLOCKED};
	}
	if (ctap_client_pin_is_boot_locked()) {
		return (CtapStatus){CTAP2_ERR_PIN_AUTH_BLOCKED};
	}

	switch (CP.subCommand) {
	case CP_SubCmd_changePIN:
		printf1(TAG_CP, "CP_SubCmd_changePIN\n");

		if (!ctap_client_pin_is_set()) {
			return (CtapStatus){CTAP2_ERR_PIN_NOT_SET};
		}

		if (!CP.newPinEncSize || !CP.pinUvAuthParam_present ||
		    !CP.keyAgreementPresent || !CP.pinHashEncPresent) {
			return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
		}

		ctap_ret = update_pin_if_verified(
		    CP.newPinEnc, CP.newPinEncSize,
		    (uint8_t *)&CP.keyAgreement.pubkey, CP.pinUvAuthParam,
		    CP.pinHashEnc, CP.pinProtocol);
		ctap_check_retr(ctap_ret);
		break;

	case CP_SubCmd_getPinToken:
		printf1(TAG_CP, "CP_SubCmd_getPinToken\n");

		if (!ctap_client_pin_is_set()) {
			return (CtapStatus){CTAP2_ERR_PIN_NOT_SET};
		}

		if (!CP.keyAgreementPresent || !CP.pinHashEncPresent) {
			printf2(TAG_ERR,
				"Error, missing keyAgreement or pinHashEnc for "
				"getPinToken\n");
			return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
		}

		// Permissions and RPID is not allowed
		if (CP.permissionsPresent || CP.permissions != 0 ||
		    CP.rpIdSize > 0) {
			return (CtapStatus){CTAP1_ERR_INVALID_PARAMETER};
		}

		cbor_ret = cbor_encoder_create_map(encoder, &map, 1);
		cbor_check_ret(cbor_ret);

		cbor_ret = cbor_encode_int(&map, CP_Resp_pinUvAuthToken);
		cbor_check_ret(cbor_ret);

		ctap_ret = add_enc_pinUvAuthToken(
		    pinTokenEnc, (uint8_t *)&CP.keyAgreement.pubkey,
		    CP.pinHashEnc, CP.pinProtocol,
		    CP_pinUvAuthToken_permissions_default_mask, CP.rpId, 0);
		ctap_check_retr(ctap_ret);

		pinTokenEncLen = (CP.pinProtocol == 2)
				     ? (CP_IV_SIZE + PINUVAUTHTOKEN_SIZE)
				     : PINUVAUTHTOKEN_SIZE;

		cbor_ret =
		    cbor_encode_byte_string(&map, pinTokenEnc, pinTokenEncLen);
		cbor_check_ret(cbor_ret);

		cbor_ret = cbor_encoder_close_container(encoder, &map);
		cbor_check_ret(cbor_ret);

		/* getPinToken grants no specific permissions (full token) */
		break;

	case CP_SubCmd_getPinUvAuthTokenUsingPinWithPermissions:
		printf1(TAG_CP,
			"CP_SubCmd_getPinUvAuthTokenUsingPinWithPermissions\n");

		if (!ctap_client_pin_is_set()) {
			return (CtapStatus){CTAP2_ERR_PIN_NOT_SET};
		}
		if (!CP.keyAgreementPresent || !CP.pinHashEncPresent) {
			return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
		}
		if (!CP.permissionsPresent || CP.permissions == 0) {
			return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
		}

		// Filter undefined permissions (they are to be ignored)
		CP.permissions &= CP_pinUvAuthToken_permissions_defined_mask;

		// Not OK by spec to request permissions for unsupported
		// features
		if (CP.permissions &
		    CP_pinUvAuthToken_permissions_unsupported_mask) {
			return (CtapStatus){CTAP2_ERR_UNAUTHORIZED_PERMISSION};
		}

		uint8_t rp_id_required =
		    CP.permissions & (CP_pinUvAuthToken_permissions_mc |
				      CP_pinUvAuthToken_permissions_ga);

		if (rp_id_required && (CP.rpIdSize == 0)) {
			return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
		}

		cbor_ret = cbor_encoder_create_map(encoder, &map, 1);
		cbor_check_ret(cbor_ret);

		cbor_ret = cbor_encode_int(&map, CP_Resp_pinUvAuthToken);
		cbor_check_ret(cbor_ret);

		ctap_ret = add_enc_pinUvAuthToken(
		    pinTokenEnc, (uint8_t *)&CP.keyAgreement.pubkey,
		    CP.pinHashEnc, CP.pinProtocol, CP.permissions, CP.rpId,
		    CP.rpIdSize);
		ctap_check_retr(ctap_ret);

		pinTokenEncLen = (CP.pinProtocol == 2)
				     ? (CP_IV_SIZE + PINUVAUTHTOKEN_SIZE)
				     : PINUVAUTHTOKEN_SIZE;

		cbor_ret =
		    cbor_encode_byte_string(&map, pinTokenEnc, pinTokenEncLen);
		cbor_check_ret(cbor_ret);

		cbor_ret = cbor_encoder_close_container(encoder, &map);
		cbor_check_ret(cbor_ret);

		break;

	// Subcommands not supported, so compress into the default state.
	// case CP_SubCmd_getPinUvAuthTokenUsingUvWithPermissions:
	// case CP_SubCmd_getUVRetries:
	default:
		printf2(TAG_ERR, "Error, invalid client pin subcommand %d\n",
			CP.subCommand);
		return (CtapStatus){CTAP2_ERR_INVALID_SUBCOMMAND};
	}

	return (CtapStatus){CTAP2_OK};
}

int ctap_client_pin_initialize(void)
{
	// Regenerate pin protocol one and two
	regenerate_key_agreement(1);
	regenerate_key_agreement(2);
	reset_pinUvAuthToken(1);
	reset_pinUvAuthToken(2);

	return 0;
}

int8_t ctap_client_pin_is_boot_locked(void)
{
	return PIN_BOOT_ATTEMPTS_LEFT <= 0;
}

int8_t ctap_client_pin_is_locked(void)
{
	return STATE.remaining_tries <= 0;
}

uint8_t ctap_client_pin_is_set(void)
{
	return STATE.is_pin_set == 1;
}

/* verify(key, message, signature) → success | error  */
int ctap_client_pin_verify(const uint8_t *key, const uint8_t *message,
			   size_t message_len, const uint8_t *signature,
			   uint8_t pin_protocol)
{

	uint8_t expected[32]; /* large enough for both protocols */
	crypto_sha256_hmac_init(key, 32);
	crypto_sha256_update(message, message_len);
	crypto_sha256_hmac_final(key, 32, expected);

	size_t ap_size = auth_param_size(pin_protocol);

	if (!secure_memeq(signature, expected, ap_size)) {
		printf2(TAG_ERR, "Error, pin auth failed\n");
		dump_hex1(TAG_ERR, signature, ap_size);
		dump_hex1(TAG_ERR, expected, ap_size);
		return -1;
	}

	return 0;
}

CtapStatus ctap_client_pin_verify_auth(uint8_t *pinUvAuthParam,
				       uint8_t *clientDataHash,
				       uint8_t pin_protocol)
{
	return ctap_client_pin_verify_auth_ex(pinUvAuthParam, clientDataHash,
					      CLIENT_DATA_HASH_SIZE,
					      pin_protocol);
}

bool ctap_client_pin_permissions_rp_id_present(uint8_t pin_protocol)
{
	pinUvAuthToken_t *pinUvAuthToken = get_pin_protocol_state(pin_protocol);
	return pinUvAuthToken->state.permissions_rp_id_present;
}

// Returns true if the rp_id_hash matches the present pinUvAuthTokens
// permissions rpid hash, or if no permissions rpid hash is set.
bool ctap_client_pin_verify_permissions_rp_id(uint8_t pin_protocol,
					      uint8_t *rp_id_hash)
{
	pinUvAuthToken_t *pinUvAuthToken = get_pin_protocol_state(pin_protocol);

	if (pinUvAuthToken->state.permissions_rp_id_present) {
		if (!memeq(pinUvAuthToken->state.permissions_rp_id_hash,
			   rp_id_hash, 32)) {
			printf1(TAG_CP, "verify_permissions_rpid: not equal\n");
			return false;
		}
	}
	return true;
}

bool ctap_client_pin_verify_permissions(uint8_t pin_protocol,
					uint8_t requested_permission)
{
	pinUvAuthToken_t *pinUvAuthToken = get_pin_protocol_state(pin_protocol);

	printf1(
	    TAG_CP, "state.permissions %d (%d)\n",
	    pinUvAuthToken->state.permissions,
	    requested_permission); // Verify that the correct permission exist
	if ((pinUvAuthToken->state.permissions & requested_permission) == 0) {
		return false;
	}
	return true;
}

// verify(pinUvAuthToken, clientDataHash pinUvAuthParam).
CtapStatus ctap_client_pin_verify_auth_ex(uint8_t *pinUvAuthParam, uint8_t *buf,
					  size_t len, uint8_t pin_protocol)
{
	pinUvAuthToken_t *pinUvAuthToken = get_pin_protocol_state(pin_protocol);

	pinUvAuthToken_usage_time_observer(pin_protocol);

	// Verify that the token is in use
	if (!pinUvAuthToken->state.in_use) {
		return (CtapStatus){CTAP2_ERR_PIN_AUTH_INVALID};
	}

	int ret = ctap_client_pin_verify(pinUvAuthToken->token, buf, len,
					 pinUvAuthParam, pin_protocol);
	if (ret < 0) {
		return (CtapStatus){CTAP2_ERR_PIN_AUTH_INVALID};
	}
	return (CtapStatus){CTAP2_OK};
}

/* decapsulate(peerCoseKey) → sharedSecret | error  */
int ctap_client_pin_decapsulate(uint8_t *platform_pubkey, uint8_t pin_protocol,
				uint8_t *shared_secret_enc_key,
				uint8_t *shared_secret_mac_key)
{
	return ecdh(platform_pubkey, pin_protocol, shared_secret_enc_key,
		    shared_secret_mac_key);
}

/*
 * Returns the encrypted pinUvAuthToken if pin verifies.
 * On success writing the result to pinTokenEnc.
 *
 * Note: If authenticator is locked or boot locked should already be checked
 * before calling this internal function.
 */
static CtapStatus
add_enc_pinUvAuthToken(uint8_t *pinTokenEnc, uint8_t *platform_pubkey,
		       uint8_t *pinHashEnc, uint8_t pinProtocol,
		       uint8_t permissions, uint8_t *rp_id, size_t rp_id_size)
{
	uint8_t enc_key[32];
	uint8_t mac_key[32];
	int token_enc_len = 0;
	int ret;

	ctap_client_pin_decapsulate(platform_pubkey, pinProtocol, enc_key,
				    mac_key);

	uint32_t hash_enc_size = (pinProtocol == 2) ? 32 : 16;
	decrypt(pinHashEnc, hash_enc_size, enc_key, pinProtocol);
	/* pinHashEnc[0..15] now holds left16(SHA-256(PIN)) */

	if (!verify_against_stored_pin(pinHashEnc)) {
		printf2(TAG_ERR, "Pin does not match!\n");
		memset(enc_key, 0, sizeof(enc_key));
		memset(mac_key, 0, sizeof(mac_key));

		// Generate new keyAgreement pair
		regenerate_key_agreement(pinProtocol);
		decrement_pin_attempts();

		if (ctap_client_pin_is_locked()) {
			return (CtapStatus){CTAP2_ERR_PIN_BLOCKED};
		}

		if (ctap_client_pin_is_boot_locked()) {
			return (CtapStatus){CTAP2_ERR_PIN_AUTH_BLOCKED};
		}
		return (CtapStatus){CTAP2_ERR_PIN_INVALID};
	}

	reset_pin_attempts();

	// Encrypt a new pinUvAuthToken for delivery to the platform
	// Reset all pinUvAuthTokens
	reset_pinUvAuthToken(1);
	reset_pinUvAuthToken(2);

	begin_using_pinUvAuthToken(false, pinProtocol, permissions);
	associate_permissions_rp_id(rp_id, rp_id_size, pinProtocol);

	ret = encrypt_pinUvAuthToken(pinTokenEnc, &token_enc_len, enc_key,
				     pinProtocol);
	(void)token_enc_len; /* caller derives length from protocol */

	secure_wipe(enc_key, sizeof(enc_key));
	secure_wipe(mac_key, sizeof(mac_key));

	if (ret != 0) {
		return (CtapStatus){CTAP1_ERR_OTHER};
	}

	return (CtapStatus){CTAP2_OK};
}

static void associate_permissions_rp_id(uint8_t *rp_id, size_t rp_id_size,
					uint8_t pin_protocol)
{
	if (rp_id_size > 0) {

		pinUvAuthToken_t *pinUvAuthToken =
		    get_pin_protocol_state(pin_protocol);

		uint8_t rp_id_lookup[32];
		ctap_derive_rp_id_info(
		    rp_id, rp_id_size,
		    pinUvAuthToken->state.permissions_rp_id_hash, rp_id_lookup);

		pinUvAuthToken->state.permissions_rp_id_present = true;

		printf1(TAG_CP, "Permissions_rp_id: :\n");
		dump_hex1(TAG_CP, pinUvAuthToken->state.permissions_rp_id_hash,
			  32);
	}
}

/*
 * Return the pinUvAuthParam / pinHashEnc size for the given protocol.
 */
static inline size_t auth_param_size(int proto)
{
	return (proto == 2) ? 32 : 16;
}

static uint8_t decrement_pin_attempts(void)
{
	if (PIN_BOOT_ATTEMPTS_LEFT > 0) {
		PIN_BOOT_ATTEMPTS_LEFT--;
	}
	if (!ctap_client_pin_is_locked()) {
		STATE.remaining_tries--;
		ctap_flush_state();
		printf1(TAG_CP, "ATTEMPTS left: %d\n", STATE.remaining_tries);

		if (ctap_client_pin_is_locked()) {
			lock_device_permanently();
		}
	} else {
		printf1(TAG_CP, "Device locked!\n");
		return (uint8_t)-1;
	}
	return 0;
}

/*
 * decrypt(key, demCiphertext) → plaintext | error
 * Decrypt |len| bytes of |buf| in-place using |enc_key|.
 *
 * Protocol 1: iv = all-zeros
 * Protocol 2: iv = first 16 bytes of |buf|
 */
static void decrypt(uint8_t *buf, uint32_t len, const uint8_t *enc_key,
		    uint8_t pin_protocol)
{
	if (pin_protocol == 1) {
		crypto_aes256_init(enc_key, NULL);
		crypto_aes256_decrypt(buf, len);
	} else {
		/* Extract IV */
		assert(len > CP_IV_SIZE);

		uint8_t iv[CP_IV_SIZE];
		memcpy(iv, buf, CP_IV_SIZE);
		uint32_t ciphertext_len = len - CP_IV_SIZE;
		/* Decrypt in-place */
		crypto_aes256_init(enc_key, iv);
		crypto_aes256_decrypt(buf + CP_IV_SIZE, ciphertext_len);
		/* Shift plaintext to front */
		memmove(buf, buf + CP_IV_SIZE, ciphertext_len);
		memset(buf + ciphertext_len, 0,
		       CP_IV_SIZE); /* zero trailing IV region */
	}
}

/* ecdh(peerCoseKey) → sharedSecret | error  */
static int ecdh(uint8_t *platform_pubkey, uint8_t pin_protocol,
		uint8_t *shared_secret_enc_key, uint8_t *shared_secret_mac_key)
{

	pinUvAuthToken_t *pinUvAuthToken = get_pin_protocol_state(pin_protocol);

	uint8_t shared_point[32];
	crypto_ecc256_shared_secret(platform_pubkey,
				    pinUvAuthToken->key_agreement.priv_key,
				    shared_point);
	kdf(shared_point, pin_protocol, shared_secret_enc_key,
	    shared_secret_mac_key);
	secure_wipe(shared_point, sizeof(shared_point));
	return 0;
}

/*
 * encrypt(key, pinUvAuthToken) →  ic || ciphertext
 * Encrypt pinUvAuthToken into |out|
 * Protocol 1: out_len = PINUVAUTHTOKEN_SIZE bytes
 * Protocol 2: out_len = 16-byte-iv + PINUVAUTHTOKEN_SIZE bytes
 *
 * Caller must ensure |out| is large enough: PINUVAUTHTOKEN_SIZE + 16.
 */
static int encrypt_pinUvAuthToken(uint8_t *out, int *out_len,
				  const uint8_t *enc_key, uint8_t pin_protocol)
{

	pinUvAuthToken_t *pinUvAuthToken = get_pin_protocol_state(pin_protocol);

	if (pin_protocol == 1) {

		crypto_aes256_init(enc_key, NULL);
		memcpy(out, pinUvAuthToken->token, PINUVAUTHTOKEN_SIZE);
		crypto_aes256_encrypt(out, PINUVAUTHTOKEN_SIZE);
		*out_len = PINUVAUTHTOKEN_SIZE;

	} else {
		/* Generate random IV */
		uint8_t iv[CP_IV_SIZE];
		if (ctap_generate_rng(iv, CP_IV_SIZE) != 1) {
			return -1;
		}
		memcpy(out, iv, CP_IV_SIZE);
		memcpy(out + CP_IV_SIZE, pinUvAuthToken->token,
		       PINUVAUTHTOKEN_SIZE);

		crypto_aes256_init(enc_key, iv);
		crypto_aes256_encrypt(out + CP_IV_SIZE, PINUVAUTHTOKEN_SIZE);
		*out_len = CP_IV_SIZE + PINUVAUTHTOKEN_SIZE;
	}
	return 0;
}

static pinUvAuthToken_t *get_pin_protocol_state(uint8_t pin_protocol)
{
	if (pin_protocol == 1) {
		return &pinUvAuthToken_p1;
	} else {
		return &pinUvAuthToken_p2;
	}
}

#define HKDF_INFO_AES "CTAP2 AES key"
#define HKDF_INFO_HMAC "CTAP2 HMAC key"

/*
 * Key derivation functions for PIN/UV Auth Protocol one and two
 * Derives session keys from the raw ECDH output.
 *
 * protocol 1: shared_secret_enc_key and shared_secret_mac_key = SHA-256(raw)
 * protocol 2: shared_secret_enc_key = HKDF(ikm=SHA-256(raw), info=AES_INFO)
 *             shared_secret_mac_key = HKDF(ikm=SHA-256(raw), info=HMAC_INFO)
 *
 * All output buffers are 32 bytes.
 */
static void kdf(const uint8_t *ikm, int pin_protocol,
		uint8_t *shared_secret_enc_key, uint8_t *shared_secret_mac_key)
{

	if (pin_protocol == 1) {
		/* Protocol 1: SHA-256(rawSecret) */
		crypto_sha256_init();
		crypto_sha256_update(ikm, 32);
		crypto_sha256_final(shared_secret_enc_key);
		memcpy(shared_secret_mac_key, shared_secret_enc_key,
		       32); /* same key for proto 1 */
	} else {
		/* Protocol 2: two HKDF-SHA-256 derivations, salt = 32×0x00 */
		uint8_t prk[32];
		crypto_hkdf_extract_sha256(NULL, 0, ikm, 32, prk);
		crypto_hkdf_expand_sha256(prk, (const uint8_t *)HKDF_INFO_AES,
					  sizeof(HKDF_INFO_AES) - 1,
					  shared_secret_enc_key, 32);

		crypto_hkdf_expand_sha256(prk, (const uint8_t *)HKDF_INFO_HMAC,
					  sizeof(HKDF_INFO_HMAC) - 1,
					  shared_secret_mac_key, 32);
		secure_wipe(prk, 32);
	}
}

static uint8_t leftover_pin_attempts(void)
{
	if (STATE.remaining_tries <= 0) {
		return 0;
	}
	return (uint8_t)STATE.remaining_tries;
}

static void lock_device_permanently(void)
{
	memset(pinUvAuthToken_p1.token, 0, PINUVAUTHTOKEN_SIZE);
	memset(pinUvAuthToken_p2.token, 0, PINUVAUTHTOKEN_SIZE);
	memset(STATE.PIN_CODE_HASH, 0, sizeof(STATE.PIN_CODE_HASH));

	printf1(TAG_CP, "Device permanently locked!\n");

	authenticator_write_state(&STATE);
}

static CtapStatus parse_client_pin_request(CTAP_clientPin *CP, uint8_t *request,
					   size_t length)
{
	CborError cbor_ret;
	CtapStatus ctap_ret;
	unsigned int i;
	int key;
	size_t map_length;
	size_t sz;
	CborParser parser;
	CborValue it;
	CborValue map;

	memset(CP, 0, sizeof(CTAP_clientPin));

	cbor_ret = cbor_parser_init(request, length,
				    CborValidateCanonicalFormat, &parser, &it);
	cbor_check_ret(cbor_ret);

	if (cbor_value_get_type(&it) != CborMapType) {
		printf2(TAG_ERR, "Error, expecting cbor map\n");
		return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
	}

	cbor_ret = cbor_value_enter_container(&it, &map);
	cbor_check_ret(cbor_ret);

	cbor_ret = cbor_value_get_map_length(&it, &map_length);
	cbor_check_ret(cbor_ret);

	printf1(TAG_CP, "CP map has %d elements\n", map_length);

	for (i = 0; i < map_length; i++) {
		if (cbor_value_get_type(&map) != CborIntegerType) {
			printf2(TAG_ERR, "Error, expecting int for map key\n");
			return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
		}

		cbor_ret = cbor_value_get_int_checked(&map, &key);
		cbor_check_ret(cbor_ret);

		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);
		cbor_ret = CborNoError;

		switch (key) {

		case CP_Cmd_pinUvAuthProtocol:
			printf1(TAG_CP, "CP_Cmd_pinUvAuthProtocol\n");
			if (cbor_value_get_type(&map) != CborIntegerType) {
				printf2(TAG_ERR,
					"Error, expecting int for map key\n");
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}

			int tmp;
			cbor_ret = cbor_value_get_int_checked(&map, &tmp);
			cbor_check_ret(cbor_ret);
			if (tmp < 0 || tmp > (int)UINT8_MAX) {
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}
			CP->pinProtocol = (uint8_t)tmp;

			break;

		case CP_Cmd_subCommand:
			printf1(TAG_CP, "CP_Cmd_subCommand\n");
			if (cbor_value_get_type(&map) != CborIntegerType) {
				printf2(TAG_ERR,
					"Error, expecting int for map key\n");
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}
			cbor_ret =
			    cbor_value_get_int_checked(&map, &CP->subCommand);
			cbor_check_ret(cbor_ret);
			break;

		case CP_Cmd_keyAgreement:
			printf1(TAG_CP, "CP_Cmd_keyAgreement\n");
			ctap_ret = cose_key_parse(&map, &CP->keyAgreement);
			ctap_check_retr(ctap_ret);
			CP->keyAgreementPresent = 1;
			break;

		case CP_Cmd_pinUvAuthParam:
			printf1(TAG_CP, "CP_Cmd_pinUvAuthParam\n");
			/*
			 * We don't yet know the protocol when parsing (it may
			 * appear later in the map), so we accept both sizes.
			 * The size is validated in ctap_client_pin() once
			 * pinProtocol is known. Store up to
			 * PIN_UV_AUTH_PARAM_MAX_SIZE bytes.
			 */
			if (cbor_value_get_type(&map) != CborByteStringType) {
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}
			sz = PIN_UV_AUTH_PARAM_MAX_SIZE;
			cbor_ret = cbor_value_copy_byte_string(
			    &map, CP->pinUvAuthParam, &sz, NULL);
			cbor_check_ret(cbor_ret);
			CP->pinUvAuthParam_present = 1;
			break;

		case CP_Cmd_newPinEnc:
			printf1(TAG_CP, "CP_Cmd_newPinEnc\n");
			if (cbor_value_get_type(&map) != CborByteStringType) {
				printf2(TAG_ERR, "Error, expecting byte string "
						 "for map key\n");
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}

			cbor_ret =
			    cbor_value_calculate_string_length(&map, &sz);
			cbor_check_ret(cbor_ret);
			if ((sz > NEW_PIN_ENC_MAX_SIZE) ||
			    (sz < NEW_PIN_ENC_MIN_SIZE)) {
				return (CtapStatus){
				    CTAP2_ERR_PIN_POLICY_VIOLATION};
			}
			CP->newPinEncSize = (uint8_t)sz;
			sz = NEW_PIN_ENC_MAX_SIZE;
			cbor_ret = cbor_value_copy_byte_string(
			    &map, CP->newPinEnc, &sz, NULL);
			cbor_check_ret(cbor_ret);
			break;

		case CP_Cmd_pinHashEnc:
			printf1(TAG_CP, "CP_Cmd_pinHashEnc\n");
			if (cbor_value_get_type(&map) != CborByteStringType) {
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}
			/*
			 * Protocol 1: 16 bytes; protocol 2: 32 bytes (IV +
			 * ciphertext). Accept up to 32 bytes here; validate
			 * exact length later.
			 */
			sz = sizeof(CP->pinHashEnc);
			cbor_ret = cbor_value_copy_byte_string(
			    &map, CP->pinHashEnc, &sz, NULL);
			cbor_check_ret(cbor_ret);
			CP->pinHashEncPresent = 1;
			break;

		case CP_Cmd_permissions:
			printf1(TAG_CP, "CP_Cmd_permissions\n");
			if (cbor_value_get_type(&map) != CborIntegerType) {
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}
			{
				int perm = 0;
				cbor_ret =
				    cbor_value_get_int_checked(&map, &perm);
				cbor_check_ret(cbor_ret);
				CP->permissions = (uint8_t)perm;
				CP->permissionsPresent = 1;
			}
			break;

		case CP_Cmd_rpId:
			printf1(TAG_CP, "CP_Cmd_rpId\n");
			if (cbor_value_get_type(&map) != CborTextStringType) {
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}
			sz = DOMAIN_NAME_MAX_SIZE;

			cbor_ret = cbor_value_copy_text_string(
			    &map, (char *)CP->rpId, &sz, NULL);
			if (cbor_ret == CborErrorOutOfMemory) {
				printf2(TAG_ERR, "Error, RP_ID is too large\n");
				return (CtapStatus){CTAP2_ERR_LIMIT_EXCEEDED};
			}
			cbor_check_ret(cbor_ret);
			CP->rpId[DOMAIN_NAME_MAX_SIZE] = '\0';
			CP->rpIdSize = sz;
			break;

		default:
			printf1(TAG_CP, "Unknown key %d\n", key);
			break;
		}

		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);
	}

	return (CtapStatus){CTAP2_OK};
}

/* regenerate(): Generate a fresh, random P-256 private key, x, and compute the
 * associated public point.
 *
 * Validates that the point is on the curve.
 *
 * The public key is computed when needed (getKeyAgreement), to prevent more
 * time at start up.
 * */
static void regenerate_key_agreement(uint8_t pin_protocol)
{
	printf1(TAG_CP, "regenerate() %d\n", pin_protocol);
	pinUvAuthToken_t *pinUvAuthToken = get_pin_protocol_state(pin_protocol);

	while (1) {
		ctap_generate_rng(
		    pinUvAuthToken->key_agreement.priv_key,
		    sizeof(pinUvAuthToken->key_agreement.priv_key));
		if (crypto_ecc256_is_valid_scalar(
			pinUvAuthToken->key_agreement.priv_key)) {
			break;
		}
	}
	pinUvAuthToken->key_agreement.pub_key_valid = false;
}

/* PIN/UV Auth Protocol Abstract Definition for authenticator
 * CTAP2.1 §6.5.4
 * */

static int reset_pinUvAuthToken(uint8_t pin_protocol)
{

	printf1(TAG_CP, "reset_token() %d\n", pin_protocol);
	pinUvAuthToken_t *pinUvAuthToken = get_pin_protocol_state(pin_protocol);

	// Initialize state to default values, currently all zero
	secure_wipe(&pinUvAuthToken->state, sizeof(pinUvAuthToken_state_t));

	if (ctap_generate_rng(pinUvAuthToken->token, PINUVAUTHTOKEN_SIZE) !=
	    1) {
		printf2(TAG_ERR, "Error, ctap_generate_rng() failed\n");
		return -1;
	}
	return 0;
}

static void reset_pin_attempts(void)
{
	if (STATE.remaining_tries == PIN_LOCKOUT_ATTEMPTS) {
		return; /* already at maximum, skip the flash write */
	}
	PIN_BOOT_ATTEMPTS_LEFT = PIN_BOOT_ATTEMPTS;
	STATE.remaining_tries = PIN_LOCKOUT_ATTEMPTS;
	ctap_flush_state();
}

// Return how many trailing zeros in a buffer
static size_t trailing_zeros(uint8_t *buf, size_t indx)
{
	size_t c = 0;
	while (indx > 0 && buf[indx] == 0) {
		indx--;
		c++;
	}
	return c;
}

/**
 * Set new PIN, by updating PIN hash. Save state.
 * Globals: STATE
 * @param pin new PIN (raw)
 * @param len pin array length
 */
static void update_pin(uint8_t *pin, size_t len)
{
	if (len >= NEW_PIN_MAX_SIZE || len < NEW_PIN_MIN_SIZE) {
		printf2(TAG_ERR, "Error, invalid pin length\n");
		exit(1);
	}

	/* Store SHA-256(left16(SHA-256(pin)) || salt) */
	crypto_sha256_init();
	crypto_sha256_update(pin, len);
	uint8_t intermediateHash[32];
	crypto_sha256_final(intermediateHash);

	crypto_sha256_init();
	crypto_sha256_update(intermediateHash, 16);
	memset(intermediateHash, 0, sizeof(intermediateHash));
	crypto_sha256_update(STATE.PIN_SALT, sizeof(STATE.PIN_SALT));
	crypto_sha256_final(STATE.PIN_CODE_HASH);

	STATE.is_pin_set = 1;
	authenticator_write_state(&STATE);

	printf1(TAG_CTAP, "New pin set: %s [%d]\n", pin, len);
	dump_hex1(TAG_CTAP, STATE.PIN_CODE_HASH, sizeof(STATE.PIN_CODE_HASH));
}

/*
 * Set or update PIN, if one already is set.
 *
 * Verifies pinUvAuthParam over (newPinEnc [|| pinHashEnc]), decrypt the new
 * PIN, optionally verify the current PIN (changePIN), before storing new pin.
 *
 * Note: If authenticator is locked or boot locked should already be checked
 * before calling this internal function if applicable.
 */
static CtapStatus
update_pin_if_verified(uint8_t *newPinEnc, uint8_t newPinEncLen,
		       uint8_t *platform_pubkey, uint8_t *pinUvAuthParam,
		       uint8_t *pinHashEnc, uint8_t pinProtocol)
{
	uint8_t enc_key[32];
	uint8_t mac_key[32];

	// newPinEnc is supposed to be 64 bytes
	if (newPinEncLen < 64) {
		return (CtapStatus){CTAP1_ERR_INVALID_PARAMETER};
	}

	ctap_client_pin_decapsulate(platform_pubkey, pinProtocol, enc_key,
				    mac_key);

	/* Verify pinUvAuthParam = authenticate(mac_key, newPinEnc [||
	 * pinHashEnc]) */
	size_t hash_enc_size = (pinProtocol == 2) ? 32 : 16;

	uint8_t tmp_verify_buf[newPinEncLen + hash_enc_size];
	uint8_t tmp_verify_buf_len = newPinEncLen;

	memcpy(tmp_verify_buf, newPinEnc, newPinEncLen);

	// If we are changing pin
	if (pinHashEnc != NULL) {
		memcpy(tmp_verify_buf + newPinEncLen, pinHashEnc,
		       hash_enc_size);
		tmp_verify_buf_len += hash_enc_size;
	}

	if (ctap_client_pin_verify(mac_key, tmp_verify_buf, tmp_verify_buf_len,
				   pinUvAuthParam, pinProtocol) < 0) {
		return (CtapStatus){CTAP2_ERR_PIN_AUTH_INVALID};
	}

	// Decrypt new PIN with shared secret
	uint32_t dec_len = newPinEncLen;

	while ((dec_len & 0xf) !=
	       0) { // Round up to nearest AES block size multiple
		dec_len++;
	}

	decrypt(newPinEnc, dec_len, enc_key, pinProtocol);

	/* Determine actual PIN length by stripping trailing zeros */
	size_t nbr_trailing_zeros =
	    trailing_zeros(newPinEnc, NEW_PIN_ENC_MIN_SIZE - 1);
	size_t newPinLen = NEW_PIN_ENC_MIN_SIZE - nbr_trailing_zeros;

	if (newPinLen < NEW_PIN_MIN_SIZE || newPinLen >= NEW_PIN_MAX_SIZE) {
		printf2(TAG_ERR,
			"New PIN is too short or too long [%d bytes]\n",
			newPinLen);
		secure_wipe(enc_key, sizeof(enc_key));
		secure_wipe(mac_key, sizeof(mac_key));
		return (CtapStatus){CTAP2_ERR_PIN_POLICY_VIOLATION};
	} else {
		printf1(TAG_CP, "New pin: %s [%d bytes]\n", newPinEnc,
			newPinLen);
		dump_hex1(TAG_CP, newPinEnc, newPinLen);
	}

	// If we are changing the current pin, decrypt and compare pinHashEnc
	// (user provided current PIN hash) with stored PIN_CODE_HASH
	if (ctap_client_pin_is_set() && pinHashEnc != NULL) {

		/* Decrypt pinHashEnc */
		decrypt(pinHashEnc, hash_enc_size, enc_key, pinProtocol);

		if (!verify_against_stored_pin(pinHashEnc)) {
			printf2(TAG_ERR, "Pin does not match!\n");
			secure_wipe(enc_key, sizeof(enc_key));
			secure_wipe(mac_key, sizeof(mac_key));

			regenerate_key_agreement(pinProtocol);
			decrement_pin_attempts();

			if (ctap_client_pin_is_locked()) {
				return (CtapStatus){CTAP2_ERR_PIN_BLOCKED};
			}
			if (ctap_client_pin_is_boot_locked()) {
				return (CtapStatus){CTAP2_ERR_PIN_AUTH_BLOCKED};
			}
			return (CtapStatus){CTAP2_ERR_PIN_INVALID};
		}

		reset_pin_attempts();
		// Reset all pinUvAuthTokens
		reset_pinUvAuthToken(1);
		reset_pinUvAuthToken(2);
	}

	secure_wipe(enc_key, sizeof(enc_key));
	secure_wipe(mac_key, sizeof(mac_key));

	// Set new PIN (update and store PIN_CODE_HASH)
	update_pin(newPinEnc, newPinLen);

	return (CtapStatus){CTAP2_OK};
}

// Verifies the pinHashEnc from the platform,  pinHashEnc =
// LEFT(SHA-256(curPin), 16)).
// Returns 1 for successful verification, otherwise zero
static int verify_against_stored_pin(uint8_t *pinHashEnc)
{
	uint8_t pinHashSalted[32];
	crypto_sha256_init();
	crypto_sha256_update(pinHashEnc, 16);
	crypto_sha256_update(STATE.PIN_SALT, sizeof(STATE.PIN_SALT));
	crypto_sha256_final(pinHashSalted);

	return memcmp(pinHashSalted, STATE.PIN_CODE_HASH, 16) == 0;
}

/* pinUvAuthToken State Maintenance Functions */

static void begin_using_pinUvAuthToken(bool user_is_present,
				       uint8_t pin_protocol,
				       uint8_t permissions)
{
	pinUvAuthToken_t *pinUvAuthToken = get_pin_protocol_state(pin_protocol);

	pinUvAuthToken->state.user_present = user_is_present;
	pinUvAuthToken->state.permissions = permissions;
	pinUvAuthToken->state.user_verified = true;
	pinUvAuthToken->state.in_use = true;
	uint32_t now = millis();
	pinUvAuthToken->state.usage_timer_start_ms = now;
	pinUvAuthToken->state.usage_timer_last_used_ms = now;

	printf1(TAG_CP,
		"begin_use permission: %d\n user_present: %d\n now: %d\n",
		permissions, user_is_present, now);

	return;
}

static void pinUvAuthToken_usage_time_observer(uint8_t pin_protocol)
{
	pinUvAuthToken_t *pinUvAuthToken = get_pin_protocol_state(pin_protocol);

	// If not in use, do nothing
	if (pinUvAuthToken->state.in_use == false) {
		return;
	}

	uint32_t now = millis();

	printf1(TAG_CP, "Time elapsed from start: %d (ms)\n",
		now - pinUvAuthToken->state.usage_timer_last_used_ms);

	// If max usage time period reach, invalidate
	if (now - pinUvAuthToken->state.usage_timer_start_ms >
	    TOKEN_MAX_USAGE_PERIOD_MS) {
		stop_using_pinUvAuthToken(pin_protocol);
	}

	// If user present time limit reached, user no longer present
	if (now - pinUvAuthToken->state.usage_timer_start_ms >
	    TOKEN_MAX_USER_PRESENT_MS) {
		ctap_client_pin_clear_user_present(pin_protocol);
	}

	// If the token is not used within 30 seconds, invalidate
	if (now - pinUvAuthToken->state.usage_timer_last_used_ms >
	    TOKEN_MAX_USER_PRESENT_MS) {
		stop_using_pinUvAuthToken(pin_protocol);
		return;
	}

	// Update rolling timer
	pinUvAuthToken->state.usage_timer_last_used_ms = now;

	return;
}

bool get_user_present(uint8_t pin_protocol)
{
	pinUvAuthToken_t *pinUvAuthToken = get_pin_protocol_state(pin_protocol);

	if (pinUvAuthToken->state.in_use) {
		return pinUvAuthToken->state.user_present;
	}
	return false;
}

bool ctap_client_pin_get_user_verified(uint8_t pin_protocol)
{

	pinUvAuthToken_t *pinUvAuthToken = get_pin_protocol_state(pin_protocol);

	if (pinUvAuthToken->state.in_use) {
		return pinUvAuthToken->state.user_verified;
	}
	return false;
}

void ctap_client_pin_clear_user_present(uint8_t pin_protocol)
{

	pinUvAuthToken_t *pinUvAuthToken = get_pin_protocol_state(pin_protocol);

	if (pinUvAuthToken->state.in_use) {
		pinUvAuthToken->state.user_present = false;
	}
}

void ctap_client_pin_clear_user_verified(uint8_t pin_protocol)
{

	pinUvAuthToken_t *pinUvAuthToken = get_pin_protocol_state(pin_protocol);

	if (pinUvAuthToken->state.in_use) {
		pinUvAuthToken->state.user_verified = false;
	}
}

void ctap_client_pin_clear_PinUvAuthToken_permissions_except_Lbw(
    uint8_t pin_protocol)
{
	pinUvAuthToken_t *pinUvAuthToken = get_pin_protocol_state(pin_protocol);

	if (pinUvAuthToken->state.in_use) {
		pinUvAuthToken->state.permissions &=
		    CP_pinUvAuthToken_permissions_lbw;
	}
}

static void stop_using_pinUvAuthToken(uint8_t pin_protocol)
{
	pinUvAuthToken_t *pinUvAuthToken = get_pin_protocol_state(pin_protocol);

	memset(&pinUvAuthToken->state, 0x00, sizeof(pinUvAuthToken_state_t));
}
