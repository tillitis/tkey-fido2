#include <stdint.h>

#include "cbor.h"
#include "cose_key.h"
#include "crypto.h"
#include "ctap.h"
#include "ctap_client_pin.h"
#include "ctap_errors.h"
#include "ctap_parse.h"
#include "ctap_reset.h"
#include "device.h"
#include "log.h"
#include "storage.h"

uint8_t KEY_AGREEMENT_PRIV[32];
uint8_t KEY_AGREEMENT_PUB[64];
uint8_t PIN_TOKEN[PIN_TOKEN_SIZE];
int8_t PIN_BOOT_ATTEMPTS_LEFT = PIN_BOOT_ATTEMPTS;

extern AuthenticatorState STATE;

static uint8_t add_pin_if_verified(uint8_t *pinTokenEnc,
				   uint8_t *platform_pubkey,
				   uint8_t *pinHashEnc);
static int8_t leftover_pin_attempts();
static void lock_device_permanently();
static uint8_t parse_client_pin_request(CTAP_clientPin *CP, uint8_t *request,
					int length);
static int trailing_zeros(uint8_t *buf, int indx);
static void update_pin(uint8_t *pin, int len);
static uint8_t update_pin_if_verified(uint8_t *pinEnc, int len,
				      uint8_t *platform_pubkey,
				      uint8_t *pinAuth, uint8_t *pinHashEnc);

uint8_t ctap_client_pin(CborEncoder *encoder, uint8_t *request, int length)
{
	CTAP_clientPin CP;
	CborEncoder map;
	uint8_t pinTokenEnc[PIN_TOKEN_SIZE];
	int ret = parse_client_pin_request(&CP, request, length);

	switch (CP.subCommand) {
	case CP_SubCmd_setPIN:
	case CP_SubCmd_changePIN:
	case CP_SubCmd_getPinToken:
		if (ctap_client_pin_is_locked()) {
			return CTAP2_ERR_PIN_BLOCKED;
		}
		if (ctap_client_pin_is_boot_locked()) {
			return CTAP2_ERR_PIN_AUTH_BLOCKED;
		}
	}

	if (ret != 0) {
		printf2(TAG_ERR, "error, parse_client_pin failed\n");
		return ret;
	}

	if (CP.pinProtocol != 1 || CP.subCommand == 0) {
		return CTAP1_ERR_OTHER;
	}

	int num_map = (CP.getRetries ? 1 : 0);

	switch (CP.subCommand) {
	case CP_SubCmd_getPINRetries:
		printf1(TAG_CP, "CP_SubCmd_getPINRetries\n");
		ret = cbor_encoder_create_map(encoder, &map, 1);
		check_ret(ret);

		CP.getRetries = 1;

		break;
	case CP_SubCmd_getKeyAgreement:
		printf1(TAG_CP, "CP_SubCmd_getKeyAgreement\n");
		num_map++;
		ret = cbor_encoder_create_map(encoder, &map, num_map);
		check_ret(ret);

		ret = cbor_encode_int(&map, CP_Resp_keyAgreement);
		check_ret(ret);

		crypto_ecc256_compute_public_key(KEY_AGREEMENT_PRIV,
						 KEY_AGREEMENT_PUB);

		ret = cose_key_add(&map, KEY_AGREEMENT_PUB,
				   KEY_AGREEMENT_PUB + 32, PUB_KEY_CRED_PUB_KEY,
				   COSE_ALG_ECDH_ES_HKDF_256);
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
					     CP.pinAuth, NULL);
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
					     CP.pinAuth, CP.pinHashEnc);
		check_retr(ret);
		break;
	case CP_SubCmd_getPinToken:
		if (!ctap_client_pin_is_set()) {
			return CTAP2_ERR_PIN_NOT_SET;
		}
		num_map++;
		ret = cbor_encoder_create_map(encoder, &map, num_map);
		check_ret(ret);

		printf1(TAG_CP, "CP_SubCmd_getPinToken\n");
		if (CP.keyAgreementPresent == 0 || CP.pinHashEncPresent == 0) {
			printf2(TAG_ERR, "Error, missing keyAgreement or "
					 "pinHashEnc for cmdGetPin\n");
			return CTAP2_ERR_MISSING_PARAMETER;
		}
		ret = cbor_encode_int(&map, CP_Resp_pinUvAuthToken);
		check_ret(ret);

		/*ret = ctap_add_pin_if_verified(&map,
		 * (uint8_t*)&CP.keyAgreement.pubkey, CP.pinHashEnc);*/
		ret = add_pin_if_verified(pinTokenEnc,
					  (uint8_t *)&CP.keyAgreement.pubkey,
					  CP.pinHashEnc);
		check_retr(ret);

		ret =
		    cbor_encode_byte_string(&map, pinTokenEnc, PIN_TOKEN_SIZE);
		check_ret(ret);

		break;

	default:
		printf2(TAG_ERR, "Error, invalid client pin subcommand\n");
		return CTAP1_ERR_OTHER;
	}

	if (CP.getRetries) {
		ret = cbor_encode_int(&map, CP_Resp_pinRetries);
		check_ret(ret);
		ret = cbor_encode_int(&map, leftover_pin_attempts());
		check_ret(ret);
	}

	if (num_map || CP.getRetries) {
		ret = cbor_encoder_close_container(encoder, &map);
		check_ret(ret);
	}

	return 0;
}

uint8_t ctap_client_pin_decrement_attempts()
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
		return -1;
	}
	return 0;
}

int8_t ctap_client_pin_is_boot_locked()
{
	return PIN_BOOT_ATTEMPTS_LEFT <= 0;
}

int8_t ctap_client_pin_is_locked()
{
	return STATE.remaining_tries <= 0;
}

uint8_t ctap_client_pin_is_set()
{
	return STATE.is_pin_set == 1;
}

void ctap_client_pin_reset_attempts()
{
	if (STATE.remaining_tries == PIN_LOCKOUT_ATTEMPTS) {
		// no need to write to flash
		return;
	}

	STATE.remaining_tries = PIN_LOCKOUT_ATTEMPTS;
	PIN_BOOT_ATTEMPTS_LEFT = PIN_BOOT_ATTEMPTS;
	ctap_flush_state();
}

uint8_t ctap_client_pin_verify_auth(uint8_t *pinAuth, uint8_t *clientDataHash)
{
	return ctap_client_pin_verify_auth_ex(pinAuth, clientDataHash,
					      CLIENT_DATA_HASH_SIZE);
}

uint8_t ctap_client_pin_verify_auth_ex(uint8_t *pinAuth, uint8_t *buf,
				       size_t len)
{
	uint8_t hmac[32];

	crypto_sha256_hmac_init(PIN_TOKEN, PIN_TOKEN_SIZE);
	crypto_sha256_update(buf, len);
	crypto_sha256_hmac_final(PIN_TOKEN, PIN_TOKEN_SIZE, hmac);

	if (memcmp(pinAuth, hmac, 16) == 0) {
		return 0;
	} else {
		printf2(TAG_ERR, "Pin auth failed\n");
		dump_hex1(TAG_ERR, pinAuth, 16);
		dump_hex1(TAG_ERR, hmac, 16);
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
}

static uint8_t add_pin_if_verified(uint8_t *pinTokenEnc,
				   uint8_t *platform_pubkey,
				   uint8_t *pinHashEnc)
{
	uint8_t shared_secret[32];

	crypto_ecc256_shared_secret(platform_pubkey, KEY_AGREEMENT_PRIV,
				    shared_secret);

	crypto_sha256_init();
	crypto_sha256_update(shared_secret, 32);
	crypto_sha256_final(shared_secret);

	crypto_aes256_init(shared_secret, NULL);

	crypto_aes256_decrypt(pinHashEnc, 16);

	uint8_t pinHashEncSalted[32];
	crypto_sha256_init();
	crypto_sha256_update(pinHashEnc, 16);
	crypto_sha256_update(STATE.PIN_SALT, sizeof(STATE.PIN_SALT));
	crypto_sha256_final(pinHashEncSalted);
	if (memcmp(pinHashEncSalted, STATE.PIN_CODE_HASH, 16) != 0) {
		printf2(TAG_ERR, "Pin does not match!\n");
		printf2(TAG_ERR, "platform-pin-hash:\n");
		dump_hex1(TAG_ERR, pinHashEnc, 16);
		printf2(TAG_ERR, "authentic-pin-hash:\n");
		dump_hex1(TAG_ERR, STATE.PIN_CODE_HASH, 16);
		printf2(TAG_ERR, "shared-secret:\n");
		dump_hex1(TAG_ERR, shared_secret, 32);
		printf2(TAG_ERR, "platform-pubkey:\n");
		dump_hex1(TAG_ERR, platform_pubkey, 64);
		printf2(TAG_ERR, "device-pubkey:\n");
		dump_hex1(TAG_ERR, KEY_AGREEMENT_PUB, 64);
		// Generate new keyAgreement pair
		ctap_reset_key_agreement();
		ctap_client_pin_decrement_attempts();
		if (ctap_client_pin_is_boot_locked()) {
			return CTAP2_ERR_PIN_AUTH_BLOCKED;
		}
		return CTAP2_ERR_PIN_INVALID;
	}

	ctap_client_pin_reset_attempts();
	crypto_aes256_reset_iv(NULL);

	memmove(pinTokenEnc, PIN_TOKEN, PIN_TOKEN_SIZE);
	crypto_aes256_encrypt(pinTokenEnc, PIN_TOKEN_SIZE);

	return 0;
}

static int8_t leftover_pin_attempts()
{
	return STATE.remaining_tries;
}

static void lock_device_permanently()
{
	memset(PIN_TOKEN, 0, sizeof(PIN_TOKEN));
	memset(STATE.PIN_CODE_HASH, 0, sizeof(STATE.PIN_CODE_HASH));

	printf1(TAG_CP, "Device locked!\n");

	authenticator_write_state(&STATE);
}

static uint8_t parse_client_pin_request(CTAP_clientPin *CP, uint8_t *request,
					int length)
{
	int ret;
	unsigned int i;
	int key;
	size_t map_length;
	size_t sz;
	CborParser parser;
	CborValue it, map;

	memset(CP, 0, sizeof(CTAP_clientPin));
	ret = cbor_parser_init(request, length, CborValidateCanonicalFormat,
			       &parser, &it);
	check_ret(ret);

	CborType type = cbor_value_get_type(&it);
	if (type != CborMapType) {
		printf2(TAG_ERR, "Error, expecting cbor map\n");
		return CTAP2_ERR_INVALID_CBOR;
	}

	ret = cbor_value_enter_container(&it, &map);
	check_ret(ret);

	ret = cbor_value_get_map_length(&it, &map_length);
	check_ret(ret);

	printf1(TAG_CP, "CP map has %d elements\n", map_length);

	for (i = 0; i < map_length; i++) {
		type = cbor_value_get_type(&map);
		if (type != CborIntegerType) {
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
			if (cbor_value_get_type(&map) == CborIntegerType) {
				cbor_value_get_int_checked(&map,
							   &CP->pinProtocol);
				check_ret(ret);
			} else {
				return CTAP2_ERR_INVALID_CBOR;
			}
			break;
		case CP_Cmd_subCommand:
			printf1(TAG_CP, "CP_Cmd_subCommand\n");
			if (cbor_value_get_type(&map) == CborIntegerType) {
				cbor_value_get_int_checked(&map,
							   &CP->subCommand);
				check_ret(ret);
			} else {
				return CTAP2_ERR_INVALID_CBOR;
			}

			break;
		case CP_Cmd_keyAgreement:
			printf1(TAG_CP, "CP_Cmd_keyAgreement\n");
			ret = cose_key_parse(&map, &CP->keyAgreement);
			check_retr(ret);
			CP->keyAgreementPresent = 1;
			break;
		case CP_Cmd_pinUvAuthParam:
			printf1(TAG_CP, "CP_Cmd_pinUvAuthParam\n");

			ret = ctap_parse_fixed_length_byte_string(
			    &map, CP->pinAuth, 16);
			check_retr(ret);
			CP->pinAuthPresent = 1;
			break;
		case CP_Cmd_newPinEnc:
			printf1(TAG_CP, "CP_Cmd_newPinEnc\n");
			if (cbor_value_get_type(&map) == CborByteStringType) {
				ret = cbor_value_calculate_string_length(&map,
									 &sz);
				check_ret(ret);
				if (sz > NEW_PIN_ENC_MAX_SIZE ||
				    sz < NEW_PIN_ENC_MIN_SIZE) {
					return CTAP2_ERR_PIN_POLICY_VIOLATION;
				}

				CP->newPinEncSize = sz;
				sz = NEW_PIN_ENC_MAX_SIZE;
				ret = cbor_value_copy_byte_string(
				    &map, CP->newPinEnc, &sz, NULL);
				check_ret(ret);
			} else {
				return CTAP2_ERR_INVALID_CBOR;
			}

			break;
		case CP_Cmd_pinHashEnc:
			printf1(TAG_CP, "CP_Cmd_pinHashEnc\n");

			ret = ctap_parse_fixed_length_byte_string(
			    &map, CP->pinHashEnc, 16);
			check_retr(ret);
			CP->pinHashEncPresent = 1;

			break;
		// TODO - Remove?
		/*
		case CP_getKeyAgreement:
			printf1(TAG_CP, "CP_getKeyAgreement\n");
			if (cbor_value_get_type(&map) != CborBooleanType) {
				printf2(TAG_ERR,
					"Error, expecting cbor boolean\n");
				return CTAP2_ERR_INVALID_CBOR;
			}
			ret =
			    cbor_value_get_boolean(&map, &CP->getKeyAgreement);
			check_ret(ret);
			break;
		case CP_getRetries:
			printf1(TAG_CP, "CP_getRetries\n");
			if (cbor_value_get_type(&map) != CborBooleanType) {
				printf2(TAG_ERR,
					"Error, expecting cbor boolean\n");
				return CTAP2_ERR_INVALID_CBOR;
			}
			ret = cbor_value_get_boolean(&map, &CP->getRetries);
			check_ret(ret);
			break;
		*/
		case CP_Cmd_permissions:
			printf1(TAG_CP, "CP_Cmd_permissions\n");
			break;
		case CP_Cmd_rpId:
			printf1(TAG_CP, "CP_Cmd_rpId\n");
			break;
		default:
			printf1(TAG_CP, "Unknown key %d\n", key);
		}

		ret = cbor_value_advance(&map);
		check_ret(ret);
	}

	return 0;
}

// Return how many trailing zeros in a buffer
static int trailing_zeros(uint8_t *buf, int indx)
{
	int c = 0;
	while (0 == buf[indx] && indx) {
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
	if (len >= NEW_PIN_ENC_MIN_SIZE || len < 4) {
		printf2(TAG_ERR, "Update pin fail length\n");
		exit(1);
	}

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

uint8_t update_pin_if_verified(uint8_t *pinEnc, int len,
			       uint8_t *platform_pubkey, uint8_t *pinAuth,
			       uint8_t *pinHashEnc)
{
	uint8_t shared_secret[32];
	uint8_t hmac[32];
	int ret;

	//    Validate incoming data packet len
	if (len < 64) {
		return CTAP1_ERR_OTHER;
	}

	//    Validate device's state
	if (ctap_client_pin_is_set()) // Check first, prevent SCA
	{
		if (ctap_client_pin_is_locked()) {
			return CTAP2_ERR_PIN_BLOCKED;
		}
		if (ctap_client_pin_is_boot_locked()) {
			return CTAP2_ERR_PIN_AUTH_BLOCKED;
		}
	}

	//    calculate shared_secret
	crypto_ecc256_shared_secret(platform_pubkey, KEY_AGREEMENT_PRIV,
				    shared_secret);

	crypto_sha256_init();
	crypto_sha256_update(shared_secret, 32);
	crypto_sha256_final(shared_secret);

	crypto_sha256_hmac_init(shared_secret, 32);
	crypto_sha256_update(pinEnc, len);
	if (pinHashEnc != NULL) {
		crypto_sha256_update(pinHashEnc, 16);
	}
	crypto_sha256_hmac_final(shared_secret, 32, hmac);

	if (memcmp(hmac, pinAuth, 16) != 0) {
		printf2(TAG_ERR, "pinAuth failed for update pin\n");
		dump_hex1(TAG_ERR, hmac, 16);
		dump_hex1(TAG_ERR, pinAuth, 16);
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}

	//     decrypt new PIN with shared secret
	crypto_aes256_init(shared_secret, NULL);

	while ((len & 0xf) != 0) // round up to nearest  AES block size multiple
	{
		len++;
	}

	crypto_aes256_decrypt(pinEnc, len);

	//      validate new PIN (length)

	ret = trailing_zeros(pinEnc, NEW_PIN_ENC_MIN_SIZE - 1);
	ret = NEW_PIN_ENC_MIN_SIZE - ret;

	if (ret < NEW_PIN_MIN_SIZE || ret >= NEW_PIN_MAX_SIZE) {
		printf2(TAG_ERR,
			"new PIN is too short or too long [%d bytes]\n", ret);
		return CTAP2_ERR_PIN_POLICY_VIOLATION;
	} else {
		printf1(TAG_CP, "new pin: %s [%d bytes]\n", pinEnc, ret);
		dump_hex1(TAG_CP, pinEnc, ret);
	}

	//    validate device's state, decrypt and compare pinHashEnc (user
	//    provided current PIN hash) with stored PIN_CODE_HASH

	if (ctap_client_pin_is_set()) {
		if (ctap_client_pin_is_locked()) {
			return CTAP2_ERR_PIN_BLOCKED;
		}
		if (ctap_client_pin_is_boot_locked()) {
			return CTAP2_ERR_PIN_AUTH_BLOCKED;
		}
		crypto_aes256_reset_iv(NULL);
		crypto_aes256_decrypt(pinHashEnc, 16);

		uint8_t pinHashEncSalted[32];
		crypto_sha256_init();
		crypto_sha256_update(pinHashEnc, 16);
		crypto_sha256_update(STATE.PIN_SALT, sizeof(STATE.PIN_SALT));
		crypto_sha256_final(pinHashEncSalted);

		if (memcmp(pinHashEncSalted, STATE.PIN_CODE_HASH, 16) != 0) {
			ctap_reset_key_agreement();
			ctap_client_pin_decrement_attempts();
			if (ctap_client_pin_is_boot_locked()) {
				return CTAP2_ERR_PIN_AUTH_BLOCKED;
			}
			return CTAP2_ERR_PIN_INVALID;
		} else {
			ctap_client_pin_reset_attempts();
		}
	}

	//      set new PIN (update and store PIN_CODE_HASH)
	update_pin(pinEnc, ret);

	return 0;
}
