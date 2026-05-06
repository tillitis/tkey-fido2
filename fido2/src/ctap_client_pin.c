#include <stdint.h>

#include "cbor.h"
#include "cose_key.h"
#include "crypto.h"
#include "ctap_client_pin.h"
#include "ctap_errors.h"
#include "ctap_parse.h"
#include "ctap_reset.h"
#include "device.h"
#include "log.h"
#include "storage.h"

uint8_t KEY_AGREEMENT_PRIV[32];
uint8_t KEY_AGREEMENT_PUB[64];
uint8_t PIN_TOKEN[PIN_TOKEN_SIZE]; /* 32 bytes; proto-1 uses first 16 */
int8_t PIN_BOOT_ATTEMPTS_LEFT = PIN_BOOT_ATTEMPTS;

/*
 * Active PIN UV auth protocol for the current session.
 * Reset to 0 on power-up; set when a valid pinProtocol is first negotiated.
 * Both protocols may be offered simultaneously; we track whichever was used
 * most recently for token operations so verify_auth_ex can pick the right MAC.
 */
static int active_pin_protocol = 0;

extern AuthenticatorState STATE;

static uint8_t add_pin_if_verified(uint8_t *pinTokenEnc,
				   uint8_t *platform_pubkey,
				   uint8_t *pinHashEnc, int pinProtocol);
static uint8_t leftover_pin_attempts(void);
static void lock_device_permanently(void);
static uint8_t parse_client_pin_request(CTAP_clientPin *CP, uint8_t *request,
					int length);
static int trailing_zeros(uint8_t *buf, int indx);
static void update_pin(uint8_t *pin, int len);
static uint8_t update_pin_if_verified(uint8_t *pinEnc, int len,
				      uint8_t *platform_pubkey,
				      uint8_t *pinAuth, uint8_t *pinHashEnc,
				      int pinProtocol);

/* -------------------------------------------------------------------------
 * Protocol-abstraction helpers
 *
 * CTAP 2.1 §6.5.6 defines two PIN/UV auth protocols:
 *
 *   Protocol 1  – legacy
 *     • ECDH shared secret  = SHA-256(rawSecret)          [32 bytes]
 *     • encrypt(K, data)    = AES-256-CBC(K[0..31], iv=0, data)
 *     • decrypt(K, data)    = AES-256-CBC-Dec(K[0..31], iv=0, data)
 *     • authenticate(K, M)  = HMAC-SHA-256(K[0..31], M)[0..15]
 *     • pinUvAuthParam size = 16 bytes
 *     • pinHashEnc size     = 16 bytes
 *
 *   Protocol 2  – CTAP 2.1
 *     • ECDH shared secret  = HKDF-SHA-256(salt=32×0x00,
 *                                           ikm=SHA-256(rawSecret),
 *                                           info="CTAP2 AES key")  → Ke[32]
 *                           + HKDF-SHA-256(salt=32×0x00,
 *                                           ikm=SHA-256(rawSecret),
 *                                           info="CTAP2 HMAC key") → Km[32]
 *     • encrypt(Ke, data)   = AES-256-CBC(Ke, iv=random-16, data)
 *                             prepend iv → ciphertext = iv || AES(data)
 *     • decrypt(Ke, cipher) = AES-256-CBC-Dec(Ke, cipher[0..15],
 *                                               cipher[16..])
 *     • authenticate(Km, M) = HMAC-SHA-256(Km, M)       [32 bytes]
 *     • pinUvAuthParam size = 32 bytes
 *     • pinHashEnc size     = 32 bytes (iv[16] || AES(left16(sha256(pin))))
 *
 * The helpers below isolate this difference so the rest of the code
 * stays protocol-agnostic.
 * ---------------------------------------------------------------------- */

#define HKDF_INFO_AES "CTAP2 AES key"
#define HKDF_INFO_HMAC "CTAP2 HMAC key"

/*
 * HKDF-SHA-256 (RFC 5869) using the available HMAC primitives.
 *   Extract: PRK  = HMAC-SHA-256(salt, ikm)
 *   Expand:  OKM  = HMAC-SHA-256(PRK,  info || 0x01)   [single block, len≤32]
 */
static void hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt,
			size_t salt_len, const uint8_t *info, size_t info_len,
			uint8_t *out, size_t out_len)
{
	/* out_len must be ≤ 32 for this single-block implementation */
	uint8_t prk[32];
	uint8_t okm[32];
	uint8_t counter = 0x01;

	/* Extract */
	crypto_sha256_hmac_init((uint8_t *)salt, salt_len);
	crypto_sha256_update(ikm, ikm_len);
	crypto_sha256_hmac_final((uint8_t *)salt, salt_len, prk);

	/* Expand (T(1) = HMAC-SHA-256(PRK, info || 0x01)) */
	crypto_sha256_hmac_init(prk, sizeof(prk));
	crypto_sha256_update(info, info_len);
	crypto_sha256_update(&counter, 1);
	crypto_sha256_hmac_final(prk, sizeof(prk), okm);

	memcpy(out, okm, out_len);
	memset(prk, 0, sizeof(prk));
	memset(okm, 0, sizeof(okm));
}

/*
 * Derive session keys from the raw ECDH output.
 *
 * proto==1: out_enc_key = SHA-256(raw); out_mac_key = same buffer (unused
 *           distinction – the spec reuses the single key for both).
 * proto==2: out_enc_key = HKDF(ikm=SHA-256(raw), info=AES_INFO)
 *           out_mac_key = HKDF(ikm=SHA-256(raw), info=HMAC_INFO)
 *
 * All output buffers are 32 bytes.
 */
static void derive_session_keys(const uint8_t *shared_secret,	 /* 32 bytes */
				int proto, uint8_t *out_enc_key, /* 32 bytes */
				uint8_t *out_mac_key /* 32 bytes */)
{
	/* Step 1: SHA-256(rawSecret) → intermediate key material */

	if (proto == 1) {
		uint8_t ikm[32];
		crypto_sha256_init();
		crypto_sha256_update(shared_secret, 32);
		crypto_sha256_final(ikm);
		memcpy(out_enc_key, ikm, 32);
		memcpy(out_mac_key, ikm, 32); /* same key for proto 1 */
	} else {
		/* Protocol 2: two HKDF-SHA-256 derivations, salt = 32×0x00 */
		static const uint8_t zero_salt[32] = {0};
		hkdf_sha256(shared_secret, 32, zero_salt, sizeof(zero_salt),
			    (const uint8_t *)HKDF_INFO_AES,
			    sizeof(HKDF_INFO_AES) - 1, out_enc_key, 32);
		hkdf_sha256(shared_secret, 32, zero_salt, sizeof(zero_salt),
			    (const uint8_t *)HKDF_INFO_HMAC,
			    sizeof(HKDF_INFO_HMAC) - 1, out_mac_key, 32);
	}
}

/*
 * Return the pinUvAuthParam / pinHashEnc size for the given protocol.
 */
static inline int auth_param_size(int proto)
{
	return (proto == 2) ? 32 : 16;
}

/*
 * Compute the MAC over |data| of |len| bytes using |mac_key|.
 * Protocol 1 → HMAC-SHA-256 truncated to 16 bytes.
 * Protocol 2 → HMAC-SHA-256, full 32 bytes.
 * Output written to |out| (caller must supply at least auth_param_size bytes).
 */
static void compute_pin_auth(const uint8_t *mac_key, /* 32 bytes */
			     const uint8_t *data, size_t len, int proto,
			     uint8_t *out)
{
	uint8_t full_hmac[32];
	crypto_sha256_hmac_init(mac_key, 32);
	crypto_sha256_update(data, len);
	crypto_sha256_hmac_final(mac_key, 32, full_hmac);
	memcpy(out, full_hmac, auth_param_size(proto));
	memset(full_hmac, 0, sizeof(full_hmac));
}

/*
 * Decrypt |len| bytes of |buf| in-place using |enc_key|.
 *
 * Protocol 1: iv = all-zeros (implicit, matching the existing
 *             crypto_aes256_init(key, NULL) convention).
 * Protocol 2: first 16 bytes of |buf| are the explicit IV;
 *             decrypted plaintext starts at buf[16], length = len-16.
 *             We shift the result left so buf[0..] holds plaintext.
 */
static void aes_decrypt_buf(uint8_t *buf, int len, uint8_t *enc_key, int proto)
{
	if (proto == 1) {
		crypto_aes256_init(enc_key, NULL);
		crypto_aes256_decrypt(buf, len);
	} else {
		/* Extract explicit IV */
		uint8_t iv[16];
		memcpy(iv, buf, 16);
		int ciphertext_len = len - 16;
		/* Decrypt in-place at buf+16 */
		crypto_aes256_init(enc_key, iv);
		crypto_aes256_decrypt(buf + 16, ciphertext_len);
		/* Shift plaintext to front */
		memmove(buf, buf + 16, ciphertext_len);
		memset(buf + ciphertext_len, 0,
		       16); /* zero trailing IV region */
	}
}

/*
 * Encrypt PIN_TOKEN into |out| (PIN_TOKEN_SIZE bytes for proto 1,
 * 16-byte-iv + PIN_TOKEN_SIZE bytes for proto 2).
 * Caller must ensure |out| is large enough: PIN_TOKEN_SIZE + 16.
 */
static int aes_encrypt_pin_token(uint8_t *out, uint8_t *enc_key, int proto,
				 int *out_len)
{
	if (proto == 1) {
		crypto_aes256_init(enc_key, NULL);
		memcpy(out, PIN_TOKEN, PIN_TOKEN_SIZE);
		crypto_aes256_encrypt(out, PIN_TOKEN_SIZE);
		*out_len = PIN_TOKEN_SIZE;
	} else {
		/* Generate random IV */
		uint8_t iv[16];
		if (ctap_generate_rng(iv, sizeof(iv)) != 1) {
			return -1;
		}
		memcpy(out, iv, 16);
		memcpy(out + 16, PIN_TOKEN, PIN_TOKEN_SIZE);
		crypto_aes256_init(enc_key, iv);
		crypto_aes256_encrypt(out + 16, PIN_TOKEN_SIZE);
		*out_len = 16 + PIN_TOKEN_SIZE;
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
	 * Add a few bytes of margin.
	 */
	uint8_t pinTokenEnc[16 + PIN_TOKEN_SIZE + 4];
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

		ret = add_pin_if_verified(pinTokenEnc,
					  (uint8_t *)&CP.keyAgreement.pubkey,
					  CP.pinHashEnc, CP.pinProtocol);
		check_retr(ret);

		pinTokenEncLen = (CP.pinProtocol == 2) ? (16 + PIN_TOKEN_SIZE)
						       : PIN_TOKEN_SIZE;

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

		ret = add_pin_if_verified(pinTokenEnc,
					  (uint8_t *)&CP.keyAgreement.pubkey,
					  CP.pinHashEnc, CP.pinProtocol);
		check_retr(ret);

		pinTokenEncLen = (CP.pinProtocol == 2) ? (16 + PIN_TOKEN_SIZE)
						       : PIN_TOKEN_SIZE;

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

uint8_t ctap_client_pin_decrement_attempts(void)
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

void ctap_client_pin_reset_attempts(void)
{
	if ((STATE.remaining_tries == PIN_LOCKOUT_ATTEMPTS) &&
	    (PIN_BOOT_ATTEMPTS_LEFT == PIN_BOOT_ATTEMPTS)) {
		return; /* already at maximum, skip the flash write */
	}

	STATE.remaining_tries = PIN_LOCKOUT_ATTEMPTS;
	PIN_BOOT_ATTEMPTS_LEFT = PIN_BOOT_ATTEMPTS;
	ctap_flush_state();
}

void ctap_client_pin_reset_key_agreement(void)
{
	ctap_generate_rng(KEY_AGREEMENT_PRIV, sizeof(KEY_AGREEMENT_PRIV));
}

void ctap_client_pin_reset_pin_token(void)
{
	if (ctap_generate_rng(PIN_TOKEN, PIN_TOKEN_SIZE) != 1) {
		printf2(TAG_ERR, "Error, ctap_generate_rng() failed\n");
		exit(1);
	}
}

uint8_t ctap_client_pin_verify_auth(uint8_t *pinAuth, uint8_t *clientDataHash)
{
	return ctap_client_pin_verify_auth_ex(pinAuth, clientDataHash,
					      CLIENT_DATA_HASH_SIZE);
}

uint8_t ctap_client_pin_verify_auth_ex(uint8_t *pinAuth, uint8_t *buf,
				       size_t len)
{
	uint8_t expected[32]; /* large enough for both protocols */
	int ap_size = auth_param_size(active_pin_protocol);

	compute_pin_auth(PIN_TOKEN, buf, len, active_pin_protocol, expected);

	if (memcmp(pinAuth, expected, ap_size) != 0) {
		printf2(TAG_ERR, "Error, pin auth failed\n");
		dump_hex1(TAG_ERR, pinAuth, ap_size);
		dump_hex1(TAG_ERR, expected, ap_size);
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}

	return 0;
}

/*
 * Verify the PIN hash sent by the platform and, on success, encrypt
 * PIN_TOKEN with the shared session key, writing the result to |pinTokenEnc|.
 *
 * On failure, decrements the attempt counter and regenerates the
 * key-agreement key pair (preventing replay attacks).
 */
static uint8_t add_pin_if_verified(uint8_t *pinTokenEnc,
				   uint8_t *platform_pubkey,
				   uint8_t *pinHashEnc, int pinProtocol)
{
	uint8_t raw_secret[32];
	uint8_t enc_key[32];
	uint8_t mac_key[32];
	int token_enc_len = 0;
	int ret;

	/* Derive raw ECDH secret */
	crypto_ecc256_shared_secret(platform_pubkey, KEY_AGREEMENT_PRIV,
				    raw_secret);

	/* Derive protocol-specific session keys */
	derive_session_keys(raw_secret, pinProtocol, enc_key, mac_key);
	memset(raw_secret, 0, sizeof(raw_secret));

	/*
	 * Decrypt the platform-provided PIN hash:
	 *   proto 1: pinHashEnc = AES-256-CBC(enc_key, iv=0,
	 * left16(SHA-256(PIN))) proto 2: pinHashEnc = iv[16] ||
	 * AES-256-CBC(enc_key, iv, left16(SHA-256(PIN))) After decryption the
	 * buffer holds the raw left-16 bytes.
	 */
	int hash_enc_size = (pinProtocol == 2) ? 32 : 16;
	aes_decrypt_buf(pinHashEnc, hash_enc_size, enc_key, pinProtocol);
	/* pinHashEnc[0..15] now holds left16(SHA-256(PIN)) */

	/* Salt and compare against stored hash */
	uint8_t pinHashSalted[32];
	crypto_sha256_init();
	crypto_sha256_update(pinHashEnc, 16);
	crypto_sha256_update(STATE.PIN_SALT, sizeof(STATE.PIN_SALT));
	crypto_sha256_final(pinHashSalted);

	if (memcmp(pinHashSalted, STATE.PIN_CODE_HASH, 16) != 0) {
		printf2(TAG_ERR, "Pin does not match!\n");
		printf2(TAG_ERR, "platform-pin-hash:\n");
		dump_hex1(TAG_ERR, pinHashEnc, 16);
		printf2(TAG_ERR, "authentic-pin-hash:\n");
		dump_hex1(TAG_ERR, STATE.PIN_CODE_HASH, 16);
		printf2(TAG_ERR, "raw_secret:\n");
		dump_hex1(TAG_ERR, raw_secret, 32);
		printf2(TAG_ERR, "platform-pubkey:\n");
		dump_hex1(TAG_ERR, platform_pubkey, 64);
		printf2(TAG_ERR, "device-pubkey:\n");
		dump_hex1(TAG_ERR, KEY_AGREEMENT_PUB, 64);

		memset(enc_key, 0, sizeof(enc_key));
		memset(mac_key, 0, sizeof(mac_key));
		memset(pinHashSalted, 0, sizeof(pinHashSalted));

		// Generate new keyAgreement pair
		ctap_client_pin_reset_key_agreement();
		ctap_client_pin_decrement_attempts();

		if (ctap_client_pin_is_boot_locked()) {
			return CTAP2_ERR_PIN_AUTH_BLOCKED;
		}
		return CTAP2_ERR_PIN_INVALID;
	}

	memset(pinHashSalted, 0, sizeof(pinHashSalted));

	ctap_client_pin_reset_attempts();

	/* Encrypt PIN_TOKEN for delivery to the platform */
	ret = aes_encrypt_pin_token(pinTokenEnc, enc_key, pinProtocol,
				    &token_enc_len);
	(void)token_enc_len; /* caller derives length from protocol */

	memset(enc_key, 0, sizeof(enc_key));
	memset(mac_key, 0, sizeof(mac_key));

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
	memset(PIN_TOKEN, 0, sizeof(PIN_TOKEN));
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
static int trailing_zeros(uint8_t *buf, int indx)
{
	int c = 0;
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
 * Verify pinAuth over (newPinEnc [|| pinHashEnc]), decrypt the new PIN,
 * optionally verify the current PIN (changePIN), then call update_pin().
 */
static uint8_t update_pin_if_verified(uint8_t *pinEnc, int len,
				      uint8_t *platform_pubkey,
				      uint8_t *pinAuth, uint8_t *pinHashEnc,
				      int pinProtocol)
{
	uint8_t shared_secret[32];
	uint8_t enc_key[32];
	uint8_t mac_key[32];
	uint8_t expected_auth[32];
	int ret;

	// Validate incoming data packet len
	if (len < 64) {
		return CTAP1_ERR_OTHER;
	}

	// Validate device's state
	if (ctap_client_pin_is_set()) { // Check first, prevent SCA
		if (ctap_client_pin_is_locked()) {
			return CTAP2_ERR_PIN_BLOCKED;
		}
		if (ctap_client_pin_is_boot_locked()) {
			return CTAP2_ERR_PIN_AUTH_BLOCKED;
		}
	}

	/* Derive session keys from ECDH */
	crypto_ecc256_shared_secret(platform_pubkey, KEY_AGREEMENT_PRIV,
				    shared_secret);
	derive_session_keys(shared_secret, pinProtocol, enc_key, mac_key);
	memset(shared_secret, 0, sizeof(shared_secret));

	/* Verify pinAuth = authenticate(mac_key, newPinEnc [|| pinHashEnc]) */
	int hash_enc_size = (pinProtocol == 2) ? 32 : 16;

	crypto_sha256_hmac_init(mac_key, 32);
	crypto_sha256_update(pinEnc, len);
	if (pinHashEnc != NULL) {
		crypto_sha256_update(pinHashEnc, hash_enc_size);
	}
	crypto_sha256_hmac_final(mac_key, 32, expected_auth);

	int ap_size = auth_param_size(pinProtocol);
	if (memcmp(expected_auth, pinAuth, ap_size) != 0) {
		printf2(TAG_ERR, "pinAuth failed for update pin\n");
		dump_hex1(TAG_ERR, expected_auth, ap_size);
		dump_hex1(TAG_ERR, pinAuth, ap_size);
		memset(enc_key, 0, sizeof(enc_key));
		memset(mac_key, 0, sizeof(mac_key));
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	memset(expected_auth, 0, sizeof(expected_auth));

	// Decrypt new PIN with shared secret
	int dec_len = len;

	while ((dec_len & 0xf) !=
	       0) { // Round up to nearest AES block size multiple
		dec_len++;
	}

	aes_decrypt_buf(pinEnc, dec_len, enc_key, pinProtocol);

	/* Determine actual PIN length by stripping trailing zeros */
	ret = trailing_zeros(pinEnc, NEW_PIN_ENC_MIN_SIZE - 1);
	ret = NEW_PIN_ENC_MIN_SIZE - ret;

	if (ret < NEW_PIN_MIN_SIZE || ret >= NEW_PIN_MAX_SIZE) {
		printf2(TAG_ERR,
			"New PIN is too short or too long [%d bytes]\n", ret);
		memset(enc_key, 0, sizeof(enc_key));
		memset(mac_key, 0, sizeof(mac_key));
		return CTAP2_ERR_PIN_POLICY_VIOLATION;
	} else {
		printf1(TAG_CP, "New pin: %s [%d bytes]\n", pinEnc, ret);
		dump_hex1(TAG_CP, pinEnc, ret);
	}

	// Validate device's state, decrypt and compare pinHashEnc (user
	// provided current PIN hash) with stored PIN_CODE_HASH

	if (ctap_client_pin_is_set()) {
		if (ctap_client_pin_is_locked()) {
			memset(enc_key, 0, sizeof(enc_key));
			memset(mac_key, 0, sizeof(mac_key));
			return CTAP2_ERR_PIN_BLOCKED;
		}
		if (ctap_client_pin_is_boot_locked()) {
			memset(enc_key, 0, sizeof(enc_key));
			memset(mac_key, 0, sizeof(mac_key));
			return CTAP2_ERR_PIN_AUTH_BLOCKED;
		}

		/* Decrypt pinHashEnc; for proto 2 this includes a leading IV */
		aes_decrypt_buf(pinHashEnc, hash_enc_size, enc_key,
				pinProtocol);

		uint8_t pinHashSalted[32];
		crypto_sha256_init();
		crypto_sha256_update(pinHashEnc, 16);
		crypto_sha256_update(STATE.PIN_SALT, sizeof(STATE.PIN_SALT));
		crypto_sha256_final(pinHashSalted);

		if (memcmp(pinHashSalted, STATE.PIN_CODE_HASH, 16) != 0) {
			memset(enc_key, 0, sizeof(enc_key));
			memset(mac_key, 0, sizeof(mac_key));
			memset(pinHashSalted, 0, sizeof(pinHashSalted));
			ctap_client_pin_reset_key_agreement();
			ctap_client_pin_decrement_attempts();
			if (ctap_client_pin_is_boot_locked()) {
				return CTAP2_ERR_PIN_AUTH_BLOCKED;
			}
			return CTAP2_ERR_PIN_INVALID;
		}

		memset(pinHashSalted, 0, sizeof(pinHashSalted));
		ctap_client_pin_reset_attempts();
	}

	memset(enc_key, 0, sizeof(enc_key));
	memset(mac_key, 0, sizeof(mac_key));

	// Set new PIN (update and store PIN_CODE_HASH)
	update_pin(pinEnc, ret);

	return 0;
}
