// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdint.h>
#include <string.h>

#include "cbor.h"
#include "cose_key.h"
#include "crypto.h"
#include "ctap_client_pin.h"
#include "ctap_errors.h"
#include "ctap_parse.h"
#include "device.h"
#include "log.h"
#include "storage.h"
#include "tkey/lib.h"
#include "uECC.h"

typedef struct {
	uint8_t priv_key[32];
	uint8_t pub_key[64];
} key_agreement_t;

key_agreement_t key_agreement = {0x00};

static uint8_t
    pinUvAuthToken[PINUVAUTHTOKEN_SIZE]; /* 32 bytes; proto-1 uses first 16 */
int8_t PIN_BOOT_ATTEMPTS_LEFT = PIN_BOOT_ATTEMPTS;

/*
 * Active PIN UV auth protocol for the current session.
 * Reset to 0 on power-up; set when a valid pinProtocol is first negotiated.
 * Both protocols may be offered simultaneously; we track whichever was used
 * most recently for token operations so verify_auth_ex can pick the right MAC.
 */
static int active_pin_protocol = 0;

extern AuthenticatorState STATE;

static uint8_t add_enc_pinUvAuthToken(uint8_t *pinTokenEnc,
				      uint8_t *platform_pubkey,
				      uint8_t *pinHashEnc, int pinProtocol);
static uint8_t decrement_pin_attempts(void);
static uint8_t leftover_pin_attempts(void);
static void lock_device_permanently(void);
static uint8_t parse_client_pin_request(CTAP_clientPin *CP, uint8_t *request,
					int length);
static int reset_pinUvAuthToken(void);
static void reset_pin_attempts(void);
static size_t trailing_zeros(uint8_t *buf, size_t indx);
static void update_pin(uint8_t *pin, int len);
static uint8_t update_pin_if_verified(uint8_t *newPinEnc, int len,
				      uint8_t *platform_pubkey,
				      uint8_t *pinAuth, uint8_t *pinHashEnc,
				      int pinProtocol);
static int verify(const uint8_t *key, const uint8_t *message,
		  uint8_t message_len, const uint8_t *signature,
		  uint8_t pin_protocol);
static int decapsulate(uint8_t *platform_pubkey, uint8_t pin_protocol,
		       uint8_t *shared_secret_enc_key,
		       uint8_t *shared_secret_mac_key);

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

/* ecdh(peerCoseKey) → sharedSecret | error  */
static int ecdh(uint8_t *platform_pubkey, uint8_t pin_protocol,
		uint8_t *shared_secret_enc_key, uint8_t *shared_secret_mac_key)
{
	uint8_t shared_point[32];
	crypto_ecc256_shared_secret(platform_pubkey, key_agreement.priv_key,
				    shared_point);
	kdf(shared_point, pin_protocol, shared_secret_enc_key,
	    shared_secret_mac_key);
	secure_wipe(shared_point, sizeof(shared_point));
	return 0;
}

/*
 * Return the pinUvAuthParam / pinHashEnc size for the given protocol.
 */
static inline int auth_param_size(int proto)
{
	return (proto == 2) ? 32 : 16;
}

/*
 * decrypt(key, demCiphertext) → plaintext | error
 * Decrypt |len| bytes of |buf| in-place using |enc_key|.
 *
 * Protocol 1: iv = all-zeros
 * Protocol 2: iv = first 16 bytes of |buf|
 */
static void decrypt(uint8_t *buf, int len, const uint8_t *enc_key,
		    int pin_protocol)
{
	if (pin_protocol == 1) {
		crypto_aes256_init(enc_key, NULL);
		crypto_aes256_decrypt(buf, len);
	} else {
		/* Extract IV */
		uint8_t iv[CP_IV_SIZE];
		memcpy(iv, buf, CP_IV_SIZE);
		int ciphertext_len = len - CP_IV_SIZE;
		/* Decrypt in-place */
		crypto_aes256_init(enc_key, iv);
		crypto_aes256_decrypt(buf + CP_IV_SIZE, ciphertext_len);
		/* Shift plaintext to front */
		memmove(buf, buf + CP_IV_SIZE, ciphertext_len);
		memset(buf + ciphertext_len, 0,
		       CP_IV_SIZE); /* zero trailing IV region */
	}
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
				  const uint8_t *enc_key, int pin_protocol)
{
	if (pin_protocol == 1) {

		crypto_aes256_init(enc_key, NULL);
		memcpy(out, pinUvAuthToken, PINUVAUTHTOKEN_SIZE);
		crypto_aes256_encrypt(out, PINUVAUTHTOKEN_SIZE);
		*out_len = PINUVAUTHTOKEN_SIZE;

	} else {
		/* Generate random IV */
		uint8_t iv[CP_IV_SIZE];
		if (ctap_generate_rng(iv, CP_IV_SIZE) != 1) {
			return -1;
		}
		memcpy(out, iv, CP_IV_SIZE);
		memcpy(out + CP_IV_SIZE, pinUvAuthToken, PINUVAUTHTOKEN_SIZE);

		crypto_aes256_init(enc_key, iv);
		crypto_aes256_encrypt(out + CP_IV_SIZE, PINUVAUTHTOKEN_SIZE);
		*out_len = CP_IV_SIZE + PINUVAUTHTOKEN_SIZE;
	}
	return 0;
}

/* -------------------------------------------------------------------------
 * Public entry point
 * ---------------------------------------------------------------------- */
uint8_t ctap_client_pin(CborEncoder *encoder, uint8_t *request, int length)
{
	CTAP_clientPin CP;
	CborEncoder map;
	/*
	 * Worst-case encrypted token output: 16-byte IV + 32-byte token.
	 */

	uint8_t pinTokenEnc[CP_IV_SIZE + PINUVAUTHTOKEN_SIZE];
	int pinTokenEncLen = 0;
	int ret;

	/*
	 * Parse first – we must know subCommand before we can gate on lock
	 * state. Failure here returns immediately; CP may be partially filled.
	 */
	ret = parse_client_pin_request(&CP, request, length);
	if (ret != 0) {
		printf2(TAG_ERR, "Error, parse_client_pin_request() failed\n");
		return ret;
	}

	/* Basic sanity: pinProtocol must be 1 or 2 for CTAP 2.1 */
	if ((CP.pinProtocol != 1 && CP.pinProtocol != 2) ||
	    CP.subCommand == 0) {
		return CTAP1_ERR_OTHER;
	}

	/* Commands that touch PIN state require unlock */
	switch (CP.subCommand) {
	case CP_SubCmd_setPIN:
	case CP_SubCmd_changePIN:
	case CP_SubCmd_getPinToken:
	case CP_SubCmd_getPinUvAuthTokenUsingPinWithPermissions:
		if (ctap_client_pin_is_locked()) {
			return CTAP2_ERR_PIN_BLOCKED;
		}
		if (ctap_client_pin_is_boot_locked()) {
			return CTAP2_ERR_PIN_AUTH_BLOCKED;
		}
		break;
	default:
		break;
	}

	int num_map = (CP.getRetries ? 1 : 0);

	switch (CP.subCommand) {
	case CP_SubCmd_getPINRetries:
		printf1(TAG_CP, "CP_SubCmd_getPINRetries\n");

		ret = cbor_encoder_create_map(encoder, &map, 2);
		check_ret(ret);

		CP.getRetries = 1;

		ret = cbor_encode_int(&map, CP_Resp_pinRetries);
		check_ret(ret);
		ret = cbor_encode_uint(&map, leftover_pin_attempts());
		check_ret(ret);

		/*
		 * powerCycleState: true when further attempts require a power
		 * cycle (i.e. boot-locked but not permanently locked).
		 */
		ret = cbor_encode_int(&map, CP_Resp_powerCycleState);
		check_ret(ret);
		ret = cbor_encode_boolean(&map,
					  ctap_client_pin_is_boot_locked() &&
					      !ctap_client_pin_is_locked());
		check_ret(ret);

		ret = cbor_encoder_close_container(encoder, &map);
		check_ret(ret);
		return 0; /* early return – container already closed */

	case CP_SubCmd_getKeyAgreement:
		printf1(TAG_CP, "CP_SubCmd_getKeyAgreement\n");
		num_map++;
		ret = cbor_encoder_create_map(encoder, &map, num_map);
		check_ret(ret);

		ret = cbor_encode_int(&map, CP_Resp_keyAgreement);
		check_ret(ret);

		crypto_ecc256_compute_public_key(key_agreement.priv_key,
						 key_agreement.pub_key);

		/* cose_key_add is equivialent with getPyblicKey() and CBOR
		 * encoding the result */
		ret = cose_key_add(
		    &map, key_agreement.pub_key, key_agreement.pub_key + 32,
		    PUB_KEY_CRED_PUB_KEY, COSE_ALG_ECDH_ES_HKDF_256);
		check_retr(ret);
		break;

	case CP_SubCmd_setPIN:
		printf1(TAG_CP, "CP_SubCmd_setPIN\n");

		if (ctap_client_pin_is_set()) {
			return CTAP2_ERR_NOT_ALLOWED;
		}
		if (!CP.newPinEncSize || !CP.pinAuthPresent ||
		    !CP.keyAgreementPresent) {
			return CTAP2_ERR_MISSING_PARAMETER;
		}

		ret = update_pin_if_verified(CP.newPinEnc, CP.newPinEncSize,
					     (uint8_t *)&CP.keyAgreement.pubkey,
					     CP.pinAuth, NULL, CP.pinProtocol);
		check_retr(ret);
		break;

	case CP_SubCmd_changePIN:
		printf1(TAG_CP, "CP_SubCmd_changePIN\n");

		if (!ctap_client_pin_is_set()) {
			return CTAP2_ERR_PIN_NOT_SET;
		}

		if (!CP.newPinEncSize || !CP.pinAuthPresent ||
		    !CP.keyAgreementPresent || !CP.pinHashEncPresent) {
			return CTAP2_ERR_MISSING_PARAMETER;
		}

		ret = update_pin_if_verified(CP.newPinEnc, CP.newPinEncSize,
					     (uint8_t *)&CP.keyAgreement.pubkey,
					     CP.pinAuth, CP.pinHashEnc,
					     CP.pinProtocol);
		check_retr(ret);
		break;

	case CP_SubCmd_getPinToken:
		printf1(TAG_CP, "CP_SubCmd_getPinToken\n");

		if (!ctap_client_pin_is_set()) {
			return CTAP2_ERR_PIN_NOT_SET;
		}

		if (!CP.keyAgreementPresent || !CP.pinHashEncPresent) {
			printf2(TAG_ERR,
				"Error, missing keyAgreement or pinHashEnc for "
				"getPinToken\n");
			return CTAP2_ERR_MISSING_PARAMETER;
		}

		num_map++;
		ret = cbor_encoder_create_map(encoder, &map, num_map);
		check_ret(ret);

		ret = cbor_encode_int(&map, CP_Resp_pinUvAuthToken);
		check_ret(ret);

		ret = add_enc_pinUvAuthToken(pinTokenEnc,
					     (uint8_t *)&CP.keyAgreement.pubkey,
					     CP.pinHashEnc, CP.pinProtocol);
		check_retr(ret);

		pinTokenEncLen = (CP.pinProtocol == 2)
				     ? (CP_IV_SIZE + PINUVAUTHTOKEN_SIZE)
				     : PINUVAUTHTOKEN_SIZE;

		ret =
		    cbor_encode_byte_string(&map, pinTokenEnc, pinTokenEncLen);
		check_ret(ret);

		/* getPinToken grants no specific permissions (full token) */
		active_pin_protocol = CP.pinProtocol;
		break;

	case CP_SubCmd_getPinUvAuthTokenUsingPinWithPermissions:
		printf1(TAG_CP,
			"CP_SubCmd_getPinUvAuthTokenUsingPinWithPermissions\n");

		if (!ctap_client_pin_is_set()) {
			return CTAP2_ERR_PIN_NOT_SET;
		}
		if (!CP.keyAgreementPresent || !CP.pinHashEncPresent) {
			return CTAP2_ERR_MISSING_PARAMETER;
		}
		if (!CP.permissionsPresent || CP.permissions == 0) {
			return CTAP2_ERR_MISSING_PARAMETER;
		}

		/*
		 * Validate permission/rpId combinations per CTAP 2.1
		 * §6.5.5.7.2: mc and ga REQUIRE an rpId. be, lbw, acfg MUST NOT
		 * have an rpId.
		 */

		// TODO: Are they really forbidden..? Spec says ignored.

		{
			uint8_t rp_required =
			    CP.permissions & (CP_pinUvAuthToken_permissions_mc |
					      CP_pinUvAuthToken_permissions_ga);
			uint8_t rp_forbidden =
			    CP.permissions &
			    (CP_pinUvAuthToken_permissions_be |
			     CP_pinUvAuthToken_permissions_lbw |
			     CP_pinUvAuthToken_permissions_acfg);

			if (rp_required && !CP.rpIdPresent) {
				return CTAP2_ERR_MISSING_PARAMETER;
			}
			if (rp_forbidden && CP.rpIdPresent) {
				return CTAP1_ERR_INVALID_PARAMETER;
			}
		}

		num_map++;
		ret = cbor_encoder_create_map(encoder, &map, num_map);
		check_ret(ret);

		ret = cbor_encode_int(&map, CP_Resp_pinUvAuthToken);
		check_ret(ret);

		ret = add_enc_pinUvAuthToken(pinTokenEnc,
					     (uint8_t *)&CP.keyAgreement.pubkey,
					     CP.pinHashEnc, CP.pinProtocol);
		check_retr(ret);

		pinTokenEncLen = (CP.pinProtocol == 2)
				     ? (CP_IV_SIZE + PINUVAUTHTOKEN_SIZE)
				     : PINUVAUTHTOKEN_SIZE;

		ret =
		    cbor_encode_byte_string(&map, pinTokenEnc, pinTokenEncLen);
		check_ret(ret);

		/*
		 * TODO: bind the token to CP.permissions and CP.rpId.
		 * A full implementation stores these in a companion structure
		 * so that ctap_make_credential / ctap_get_assertion can
		 * enforce the permission scope before accepting the token.
		 */
		active_pin_protocol = CP.pinProtocol;
		break;

	case CP_SubCmd_getPinUvAuthTokenUsingUvWithPermissions:
		printf1(TAG_CP,
			"CP_SubCmd_getPinUvAuthTokenUsingUvWithPermissions\n");
		/*
		 * Requires an on-device user-verification method (biometric,
		 * etc.). Return CTAP2_ERR_INVALID_SUBCOMMAND if the
		 * authenticator does not support built-in UV; return
		 * CTAP2_ERR_UV_BLOCKED when UV is locked. Stub: indicate no
		 * built-in UV is available.
		 */
		return CTAP2_ERR_INVALID_SUBCOMMAND;

	case CP_SubCmd_getUVRetries:
		printf1(TAG_CP, "CP_SubCmd_getUVRetries\n");
		/*
		 * Only meaningful when built-in UV is supported.
		 * Return CTAP2_ERR_INVALID_SUBCOMMAND to signal no built-in UV.
		 */
		return CTAP2_ERR_INVALID_SUBCOMMAND;

	default:
		printf2(TAG_ERR, "Error, invalid client pin subcommand %d\n",
			CP.subCommand);
		return CTAP1_ERR_OTHER;
	}

	/*
	 * Append pinRetries to the map if any sub-command requested it.
	 * (getPINRetries already closed its own map and returned early.)
	 */
	if (CP.getRetries) {
		ret = cbor_encode_int(&map, CP_Resp_pinRetries);
		check_ret(ret);
		ret = cbor_encode_uint(&map, leftover_pin_attempts());
		check_ret(ret);
	}

	if (num_map || CP.getRetries) {
		ret = cbor_encoder_close_container(encoder, &map);
		check_ret(ret);
	}

	return 0;
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

static void reset_pin_attempts(void)
{
	if (STATE.remaining_tries == PIN_LOCKOUT_ATTEMPTS) {
		return; /* already at maximum, skip the flash write */
	}
	PIN_BOOT_ATTEMPTS_LEFT = PIN_BOOT_ATTEMPTS;
	STATE.remaining_tries = PIN_LOCKOUT_ATTEMPTS;
	ctap_flush_state();
}

/* regenerate(): Generate a fresh, random P-256 private key, x, and compute the
 * associated public point.
 *
 * Validates that the point is on the curve.
 *
 * The public key is computed when needed (getKeyAgreement), to prevent more
 * time at start up.
 * */
static void regenerate_key_agreement(void)
{
	while (1) {
		ctap_generate_rng(key_agreement.priv_key,
				  sizeof(key_agreement.priv_key));
		if (crypto_ecc256_is_valid_scalar(key_agreement.priv_key)) {
			break;
		}
	}
}

uint8_t ctap_client_pin_verify_auth(uint8_t *pinAuth, uint8_t *clientDataHash)
{
	return ctap_client_pin_verify_auth_ex(pinAuth, clientDataHash,
					      CLIENT_DATA_HASH_SIZE);
}

// verify(pinUvAuthToken, clientDataHash pinUvAuthParam).
uint8_t ctap_client_pin_verify_auth_ex(uint8_t *pinAuth, uint8_t *buf,
				       size_t len)
{

	// TODO: Do we know from an external request the pin protocol?
	int ret =
	    verify(pinUvAuthToken, buf, len, pinAuth, active_pin_protocol);
	if (ret < 0) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	return 0;
}

// Verifies the pinHashEnc from the platform,  pinHashEnc =
// LEFT(SHA-256(curPin), 16)).
// Returns 1 for successful verification, otherwise zero
int verify_against_stored_pin(uint8_t *pinHashEnc)
{
	uint8_t pinHashSalted[32];
	crypto_sha256_init();
	crypto_sha256_update(pinHashEnc, 16);
	crypto_sha256_update(STATE.PIN_SALT, sizeof(STATE.PIN_SALT));
	crypto_sha256_final(pinHashSalted);

	return memcmp(pinHashSalted, STATE.PIN_CODE_HASH, 16) == 0;
}

/*
 * Returns the encrypted pinUvAuthToken if pin verifies.
 * On success writing the result to pinTokenEnc.
 *
 * Note: If authenticator is locked or boot locked should already be checked
 * before calling this internal function.
 */
static uint8_t add_enc_pinUvAuthToken(uint8_t *pinTokenEnc,
				      uint8_t *platform_pubkey,
				      uint8_t *pinHashEnc, int pinProtocol)
{
	uint8_t enc_key[32];
	uint8_t mac_key[32];
	int token_enc_len = 0;
	int ret;

	decapsulate(platform_pubkey, pinProtocol, enc_key, mac_key);

	int hash_enc_size = (pinProtocol == 2) ? 32 : 16;
	decrypt(pinHashEnc, hash_enc_size, enc_key, pinProtocol);
	/* pinHashEnc[0..15] now holds left16(SHA-256(PIN)) */

	if (!verify_against_stored_pin(pinHashEnc)) {
		printf2(TAG_ERR, "Pin does not match!\n");
		printf2(TAG_ERR, "platform-pin-hash:\n");
		dump_hex1(TAG_ERR, pinHashEnc, 16);
		printf2(TAG_ERR, "authentic-pin-hash:\n");
		dump_hex1(TAG_ERR, STATE.PIN_CODE_HASH, 16);
		printf2(TAG_ERR, "platform-pubkey:\n");
		dump_hex1(TAG_ERR, platform_pubkey, 64);
		printf2(TAG_ERR, "device-pubkey:\n");
		dump_hex1(TAG_ERR, key_agreement.pub_key, 64);

		memset(enc_key, 0, sizeof(enc_key));
		memset(mac_key, 0, sizeof(mac_key));

		// Generate new keyAgreement pair
		regenerate_key_agreement();
		reset_pinUvAuthToken();
		decrement_pin_attempts();

		if (ctap_client_pin_is_locked()) {
			return CTAP2_ERR_PIN_BLOCKED;
		}

		if (ctap_client_pin_is_boot_locked()) {
			return CTAP2_ERR_PIN_AUTH_BLOCKED;
		}
		return CTAP2_ERR_PIN_INVALID;
	}

	reset_pin_attempts();

	/* Encrypt a new pinUvAuthToken for delivery to the platform */
	reset_pinUvAuthToken();
	ret = encrypt_pinUvAuthToken(pinTokenEnc, &token_enc_len, enc_key,
				     pinProtocol);
	(void)token_enc_len; /* caller derives length from protocol */

	secure_wipe(enc_key, sizeof(enc_key));
	secure_wipe(mac_key, sizeof(mac_key));

	if (ret != 0) {
		return CTAP1_ERR_OTHER;
	}

	return 0;
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
	memset(pinUvAuthToken, 0, PINUVAUTHTOKEN_SIZE);
	memset(STATE.PIN_CODE_HASH, 0, sizeof(STATE.PIN_CODE_HASH));

	printf1(TAG_CP, "Device permanently locked!\n");

	authenticator_write_state(&STATE);
}

/* -------------------------------------------------------------------------
 * CBOR parsing
 * ---------------------------------------------------------------------- */

static uint8_t parse_client_pin_request(CTAP_clientPin *CP, uint8_t *request,
					int length)
{
	int ret;
	unsigned int i;
	int key;
	size_t map_length;
	size_t sz;
	CborParser parser;
	CborValue it;
	CborValue map;

	memset(CP, 0, sizeof(CTAP_clientPin));

	ret = cbor_parser_init(request, length, CborValidateCanonicalFormat,
			       &parser, &it);
	check_ret(ret);

	if (cbor_value_get_type(&it) != CborMapType) {
		printf2(TAG_ERR, "Error, expecting cbor map\n");
		return CTAP2_ERR_INVALID_CBOR;
	}

	ret = cbor_value_enter_container(&it, &map);
	check_ret(ret);

	ret = cbor_value_get_map_length(&it, &map_length);
	check_ret(ret);

	printf1(TAG_CP, "CP map has %d elements\n", map_length);

	for (i = 0; i < map_length; i++) {
		if (cbor_value_get_type(&map) != CborIntegerType) {
			printf2(TAG_ERR, "Error, expecting int for map key\n");
			return CTAP2_ERR_INVALID_CBOR;
		}

		ret = cbor_value_get_int_checked(&map, &key);
		check_ret(ret);

		ret = cbor_value_advance(&map);
		check_ret(ret);
		ret = 0;

		switch (key) {

		case CP_Cmd_pinUvAuthProtocol:
			printf1(TAG_CP, "CP_Cmd_pinUvAuthProtocol\n");
			if (cbor_value_get_type(&map) != CborIntegerType) {
				printf2(TAG_ERR,
					"Error, expecting int for map key\n");
				return CTAP2_ERR_INVALID_CBOR;
			}

			cbor_value_get_int_checked(&map, &CP->pinProtocol);
			check_ret(ret);
			break;

		case CP_Cmd_subCommand:
			printf1(TAG_CP, "CP_Cmd_subCommand\n");
			if (cbor_value_get_type(&map) != CborIntegerType) {
				printf2(TAG_ERR,
					"Error, expecting int for map key\n");
				return CTAP2_ERR_INVALID_CBOR;
			}
			cbor_value_get_int_checked(&map, &CP->subCommand);
			check_ret(ret);
			break;

		case CP_Cmd_keyAgreement:
			printf1(TAG_CP, "CP_Cmd_keyAgreement\n");
			ret = cose_key_parse(&map, &CP->keyAgreement);
			check_retr(ret);
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
				return CTAP2_ERR_INVALID_CBOR;
			}
			sz = PIN_UV_AUTH_PARAM_MAX_SIZE;
			ret = cbor_value_copy_byte_string(&map, CP->pinAuth,
							  &sz, NULL);
			check_ret(ret);
			CP->pinAuthPresent = 1;
			break;

		case CP_Cmd_newPinEnc:
			printf1(TAG_CP, "CP_Cmd_newPinEnc\n");
			if (cbor_value_get_type(&map) != CborByteStringType) {
				printf2(TAG_ERR, "Error, expecting byte string "
						 "for map key\n");
				return CTAP2_ERR_INVALID_CBOR;
			}

			ret = cbor_value_calculate_string_length(&map, &sz);
			check_ret(ret);
			if (sz > NEW_PIN_ENC_MAX_SIZE ||
			    sz < NEW_PIN_ENC_MIN_SIZE) {
				return CTAP2_ERR_PIN_POLICY_VIOLATION;
			}

			CP->newPinEncSize = (int)sz;
			sz = NEW_PIN_ENC_MAX_SIZE;
			ret = cbor_value_copy_byte_string(&map, CP->newPinEnc,
							  &sz, NULL);
			check_ret(ret);
			break;

		case CP_Cmd_pinHashEnc:
			printf1(TAG_CP, "CP_Cmd_pinHashEnc\n");
			if (cbor_value_get_type(&map) != CborByteStringType) {
				return CTAP2_ERR_INVALID_CBOR;
			}
			/*
			 * Protocol 1: 16 bytes; protocol 2: 32 bytes (IV +
			 * ciphertext). Accept up to 32 bytes here; validate
			 * exact length later.
			 */
			sz = sizeof(CP->pinHashEnc);
			ret = cbor_value_copy_byte_string(&map, CP->pinHashEnc,
							  &sz, NULL);
			check_ret(ret);
			CP->pinHashEncPresent = 1;
			break;

		case CP_Cmd_permissions:
			printf1(TAG_CP, "CP_Cmd_permissions\n");
			if (cbor_value_get_type(&map) != CborIntegerType) {
				return CTAP2_ERR_INVALID_CBOR;
			}
			{
				int perm = 0;
				cbor_value_get_int_checked(&map, &perm);
				CP->permissions = (uint8_t)perm;
				CP->permissionsPresent = 1;
			}
			break;

		case CP_Cmd_rpId:
			printf1(TAG_CP, "CP_Cmd_rpId\n");
			if (cbor_value_get_type(&map) != CborTextStringType) {
				return CTAP2_ERR_INVALID_CBOR;
			}
			sz = CP_MAX_RPID_LEN;
			ret = cbor_value_copy_text_string(&map, CP->rpId, &sz,
							  NULL);
			check_ret(ret);
			CP->rpId[sz] = '\0';
			CP->rpIdPresent = 1;
			break;

		default:
			printf1(TAG_CP, "Unknown key %d\n", key);
			break;
		}

		ret = cbor_value_advance(&map);
		check_ret(ret);
	}

	return 0;
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
static void update_pin(uint8_t *pin, int len)
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
 * Verifies pinAuth over (newPinEnc [|| pinHashEnc]), decrypt the new PIN,
 * optionally verify the current PIN (changePIN), before storing new pin.
 *
 * Note: If authenticator is locked or boot locked should already be checked
 * before calling this internal function.
 */
static uint8_t update_pin_if_verified(uint8_t *newPinEnc, int newPinEnc_len,
				      uint8_t *platform_pubkey,
				      uint8_t *pinAuth, uint8_t *pinHashEnc,
				      int pinProtocol)
{
	uint8_t enc_key[32];
	uint8_t mac_key[32];

	// newPinEnc is suppsoed to be 64 bytes
	if (newPinEnc_len < 64) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	decapsulate(platform_pubkey, pinProtocol, enc_key, mac_key);

	/* Verify pinAuth = authenticate(mac_key, newPinEnc [|| pinHashEnc]) */
	int hash_enc_size = (pinProtocol == 2) ? 32 : 16;

	uint8_t tmp_verify_buf[newPinEnc_len + hash_enc_size];
	uint8_t tmp_verify_buf_len = newPinEnc_len;

	memcpy(tmp_verify_buf, newPinEnc, newPinEnc_len);

	// If we are changing pin
	if (pinHashEnc != NULL) {
		memcpy(tmp_verify_buf + newPinEnc_len, pinHashEnc,
		       hash_enc_size);
		tmp_verify_buf_len += hash_enc_size;
	}

	if (verify(mac_key, tmp_verify_buf, tmp_verify_buf_len, pinAuth,
		   pinProtocol) < 0) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}

	// Decrypt new PIN with shared secret
	int dec_len = newPinEnc_len;

	while ((dec_len & 0xf) !=
	       0) { // Round up to nearest AES block size multiple
		dec_len++;
	}

	decrypt(newPinEnc, dec_len, enc_key, pinProtocol);

	/* Determine actual PIN length by stripping trailing zeros */
	size_t nbr_trailing_zeros =
	    trailing_zeros(newPinEnc, NEW_PIN_ENC_MIN_SIZE - 1);
	size_t newPin_len = NEW_PIN_ENC_MIN_SIZE - nbr_trailing_zeros;

	if (newPin_len < NEW_PIN_MIN_SIZE || newPin_len >= NEW_PIN_MAX_SIZE) {
		printf2(TAG_ERR,
			"New PIN is too short or too long [%d bytes]\n",
			newPin_len);
		secure_wipe(enc_key, sizeof(enc_key));
		secure_wipe(mac_key, sizeof(mac_key));
		return CTAP2_ERR_PIN_POLICY_VIOLATION;
	} else {
		printf1(TAG_CP, "New pin: %s [%d bytes]\n", newPinEnc,
			newPin_len);
		dump_hex1(TAG_CP, newPinEnc, newPin_len);
	}

	// If we are changing the current pin, decrypt and compare pinHashEnc
	// (user provided current PIN hash) with stored PIN_CODE_HASH
	if (ctap_client_pin_is_set() && pinHashEnc != NULL) {

		/* Decrypt pinHashEnc */
		decrypt(pinHashEnc, hash_enc_size, enc_key, pinProtocol);

		if (!verify_against_stored_pin(pinHashEnc)) {
			secure_wipe(enc_key, sizeof(enc_key));
			secure_wipe(mac_key, sizeof(mac_key));

			regenerate_key_agreement();
			decrement_pin_attempts();

			if (ctap_client_pin_is_locked()) {
				return CTAP2_ERR_PIN_BLOCKED;
			}
			if (ctap_client_pin_is_boot_locked()) {
				return CTAP2_ERR_PIN_AUTH_BLOCKED;
			}
			return CTAP2_ERR_PIN_INVALID;
		}

		reset_pin_attempts();
		reset_pinUvAuthToken();
	}

	secure_wipe(enc_key, sizeof(enc_key));
	secure_wipe(mac_key, sizeof(mac_key));

	// Set new PIN (update and store PIN_CODE_HASH)
	update_pin(newPinEnc, newPin_len);

	return 0;
}

/* PIN/UV Auth Protocol Abstract Definition for authenticator
 * CTAP2.1 §6.5.4
 * */

static int reset_pinUvAuthToken(void)
{
	if (ctap_generate_rng(pinUvAuthToken, PINUVAUTHTOKEN_SIZE) != 1) {
		printf2(TAG_ERR, "Error, ctap_generate_rng() failed\n");
		return -1;
	}
	return 0;
}

int ctap_client_pin_initialize(void)
{
	regenerate_key_agreement();
	return reset_pinUvAuthToken();
}

/* decapsulate(peerCoseKey) → sharedSecret | error  */
static int decapsulate(uint8_t *platform_pubkey, uint8_t pin_protocol,
		       uint8_t *shared_secret_enc_key,
		       uint8_t *shared_secret_mac_key)
{
	return ecdh(platform_pubkey, pin_protocol, shared_secret_enc_key,
		    shared_secret_mac_key);
}

/* verify(key, message, signature) → success | error  */
static int verify(const uint8_t *key, const uint8_t *message,
		  uint8_t message_len, const uint8_t *signature,
		  uint8_t pin_protocol)
{

	uint8_t expected[32]; /* large enough for both protocols */
	crypto_sha256_hmac_init(key, 32);
	crypto_sha256_update(message, message_len);
	crypto_sha256_hmac_final(key, 32, expected);

	int ap_size = auth_param_size(active_pin_protocol);

	if (!secure_memeq(signature, expected, ap_size)) {
		printf2(TAG_ERR, "Error, pin auth failed\n");
		dump_hex1(TAG_ERR, signature, ap_size);
		dump_hex1(TAG_ERR, expected, ap_size);
		return -1;
	}

	return 0;
}
