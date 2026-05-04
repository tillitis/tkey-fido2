// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "attestation.h"
#include "cbor.h"
#include "cose_key.h"
#include "crypto.h"
#include "ctap.h"
#include "ctap_client_pin.h"
#include "ctap_credential_management.h"
#include "ctap_errors.h"
#include "ctap_get_assertion.h"
#include "ctap_get_info.h"
#include "ctap_get_next_assertion.h"
#include "ctap_make_credential.h"
#include "ctap_parse.h"
#include "ctap_reset.h"
#include "ctaphid.h"
#include "device.h"
#include "extensions.h"
#include "log.h"
#include "storage.h"
#include "u2f.h"
#include "util.h"
#include "version.h"

AuthenticatorState STATE;

struct _getAssertionState getAssertionState;

extern uint8_t PIN_TOKEN[PIN_TOKEN_SIZE];

static void derive_user_id_lookup(const uint8_t *id, size_t size,
				  uint8_t *user_id_lookup);
static int is_cred_id_matching_rk(const CredentialId *credId,
				  const CTAP_residentKey *rk);
static void truncate_rpid(uint8_t *stored_rpid, uint8_t *stored_len,
			  const uint8_t *rpid, size_t rpid_len);

int ctap2_user_presence_test()
{
	device_set_status(CTAPHID_STATUS_UPNEEDED);
	int ret = ctap_user_presence_test(CTAP2_UP_DELAY_MS);
	if (ret > 0) {
		return CTAP1_ERR_SUCCESS;
	} else if (ret < 0) {
		return CTAP2_ERR_KEEPALIVE_CANCEL;
	} else {
		return CTAP2_ERR_ACTION_TIMEOUT;
	}
}

uint32_t ctap_auth_data_update_count(CTAP_authDataHeader *authData)
{
	uint32_t count = ctap_atomic_count(0);
	if (count == 0) // count 0 will indicate invalid token
	{
		count = ctap_atomic_count(0);
	}
	uint8_t *byte = (uint8_t *)&authData->signCount;

	*byte++ = (count >> 24) & 0xff;
	*byte++ = (count >> 16) & 0xff;
	*byte++ = (count >> 8) & 0xff;
	*byte++ = (count >> 0) & 0xff;

	return count;
}

uint8_t ctap_cbor_encode_credential_descriptor(CborEncoder *map,
					       struct Credential *cred,
					       int type)
{
	CborEncoder desc;

	int ret = cbor_encoder_create_map(map, &desc, 2);
	check_ret(ret);

	{
		ret = cbor_encode_text_string(&desc, "id", 2);
		check_ret(ret);

		ret =
		    cbor_encode_byte_string(&desc, (uint8_t *)&cred->id,
					    ctap_get_credential_id_size(type));
		check_ret(ret);
	}

	{
		ret = cbor_encode_text_string(&desc, "type", 4);
		check_ret(ret);

		ret = cbor_encode_text_string(&desc, "public-key", 10);
		check_ret(ret);
	}

	ret = cbor_encoder_close_container(map, &desc);
	check_ret(ret);

	return 0;
}

uint8_t ctap_cbor_encode_user_entity(CborEncoder *map, CTAP_userEntity *user,
				     int is_verified)
{
	CborEncoder entity;
	int ret;

	/* Always include id */
	int map_size = 1;

	int dispname = (user->name[0] != 0) && is_verified;

	if (dispname) {
		map_size += 2; /* name + displayName */
	}

	ret = cbor_encoder_create_map(map, &entity, map_size);
	check_ret(ret);

	ret = cbor_encode_text_string(&entity, "id", 2);
	check_ret(ret);

	ret = cbor_encode_byte_string(&entity, user->id, user->id_size);
	check_ret(ret);

	if (dispname) {

		ret = cbor_encode_text_string(&entity, "name", 4);
		check_ret(ret);

		ret =
		    cbor_encode_text_stringz(&entity, (const char *)user->name);
		check_ret(ret);

		ret = cbor_encode_text_string(&entity, "displayName", 11);
		check_ret(ret);

		ret = cbor_encode_text_stringz(&entity,
					       (const char *)user->displayName);
		check_ret(ret);
	}

	ret = cbor_encoder_close_container(map, &entity);
	check_ret(ret);

	return 0;
}

uint8_t ctap_check_credential_metadata(CredentialId *credential,
				       uint8_t is_verified,
				       uint8_t is_from_credid_list,
				       uint8_t *is_rk)
{

	uint8_t metadata[CREDENTIAL_METADATA_SIZE];
	ctap_xcrypt_buf(credential->nonce, credential->protected_metadata,
			metadata, CREDENTIAL_METADATA_SIZE);

	uint8_t cred_protect = metadata[CREDENTIAL_META_CRED_PROTECT_BYTE];
	*is_rk = metadata[CREDENTIAL_META_FLAGS_BYTE] &
		 CREDENTIAL_META_IS_RK_BITMASK;

	switch (cred_protect) {
	case EXT_CRED_PROTECT_OPTIONAL_WITH_CREDID:
		if (!is_from_credid_list) {
			if (!is_verified) {
				return CTAP2_ERR_NOT_ALLOWED;
			}
		}
		break;
	case EXT_CRED_PROTECT_REQUIRED:
		if (!is_verified) {
			return CTAP2_ERR_NOT_ALLOWED;
		}
		break;
	}

	return 0;
}

// Return 1 if credential belongs to this token
int ctap_credential_belongs_to_rp(uint8_t *rp_id_lookup, uint8_t *rp_id_hash,
				  CTAP_credentialDescriptor *desc)
{
	uint8_t tag[16];

	switch (desc->type) {
	case PUB_KEY_CRED_PUB_KEY:

		// Verify mac and RP
		// Deliberately use the rp_id_lookup from the request, not the
		// credential, to make sure this request comes from the right
		// RP.
		ctap_make_auth_tag(rp_id_lookup, desc->credential.id.nonce,
				   desc->credential.id.protected_metadata,
				   desc->credential.id.count, tag);

		return (secure_memeq(desc->credential.id.tag, tag,
				     CREDENTIAL_TAG_SIZE) == 1);
		break;
	case PUB_KEY_CRED_CTAP1:
		return u2f_authenticate_credential(
		    (struct u2f_key_handle *)&desc->credential.id,
		    U2F_KEY_HANDLE_SIZE, rp_id_hash);
		break;
	case PUB_KEY_CRED_CUSTOM:
		return is_extension_request(getAssertionState.customCredId,
					    getAssertionState.customCredIdSize);
		break;
	default:
		printf1(TAG_ERR, "PUB_KEY_CRED_UNKNOWN %x\n", desc->type);
		break;
	}

	return 0;
}

void ctap_decrement_rk_store()
{
	STATE.rk_stored--;
	ctap_flush_state();
}

// Derives both the RPID hash and the lookup MAC from the RP ID.
// rp_id_hash   [out] Buffer of size 32
// rp_id_lookup [out] Buffer of size 16 (CREDENTIAL_TAG_SIZE)
void ctap_derive_rp_id_info(const uint8_t *rp_id, size_t size,
			    uint8_t *rp_id_hash, uint8_t *rp_id_lookup)
{
	crypto_sha256_init();
	crypto_sha256_update(rp_id, size);
	crypto_sha256_final(rp_id_hash);

	ctap_compute_mac(rp_id_hash, 32, rp_id_lookup, CREDENTIAL_TAG_SIZE);
}

/**
 * Encodes R,S signature to 2 der sequence of two integers.
 * Sigder must be at least 72 bytes.
 *
 * @param in_sigbuf IN location to deposit signature (must be 64 bytes)
 * @param out_sigder OUT location to deposit der signature (must be 72 bytes)
 * @return length of der signature
 * // FIXME add tests for maximum and minimum length of the input and output
 */
int ctap_encode_der_sig(const uint8_t *const in_sigbuf,
			uint8_t *const out_sigder)
{
	// Need to caress into dumb der format ..
	uint8_t i;
	uint8_t lead_s = 0; // leading zeros
	uint8_t lead_r = 0;
	for (i = 0; i < 32; i++) {
		if (in_sigbuf[i] == 0) {
			lead_r++;
		} else {
			break;
		}
	}

	for (i = 0; i < 32; i++) {
		if (in_sigbuf[i + 32] == 0) {
			lead_s++;
		} else {
			break;
		}
	}

	int8_t pad_s = ((in_sigbuf[32 + lead_s] & 0x80) == 0x80);
	int8_t pad_r = ((in_sigbuf[0 + lead_r] & 0x80) == 0x80);

	memset(out_sigder, 0, 72);
	out_sigder[0] = 0x30;
	out_sigder[1] = 0x44 + pad_s + pad_r - lead_s - lead_r;

	// R ingredient
	out_sigder[2] = 0x02;
	out_sigder[3 + pad_r] = 0;
	out_sigder[3] = 0x20 + pad_r - lead_r;
	memmove(out_sigder + 4 + pad_r, in_sigbuf + lead_r, 32u - lead_r);

	// S ingredient
	out_sigder[4 + 32 + pad_r - lead_r] = 0x02;
	out_sigder[5 + 32 + pad_r + pad_s - lead_r] = 0;
	out_sigder[5 + 32 + pad_r - lead_r] = 0x20 + pad_s - lead_s;
	memmove(out_sigder + 6 + 32 + pad_r + pad_s - lead_r,
		in_sigbuf + 32u + lead_s, 32u - lead_s);

	return 0x46 + pad_s + pad_r - lead_r - lead_s;
}

void ctap_flush_state()
{
	authenticator_write_state(&STATE);
}

size_t ctap_get_credential_id_size(int type)
{
	if (type == PUB_KEY_CRED_CTAP1)
		return U2F_KEY_HANDLE_SIZE;
	if (type == PUB_KEY_CRED_CUSTOM)
		return getAssertionState.customCredIdSize;
	return sizeof(CredentialId);
}

void ctap_increment_rk_store()
{
	STATE.rk_stored++;
	ctap_flush_state();
}

//  Run ctap related power-up procedures (init pinToken, generate shared secret)
void ctap_init()
{
	printf1(TAG_GREEN, "Current firmware version address: %p\n",
		&firmware_version);
	printf1(TAG_GREEN,
		"Current firmware version: %d.%d.%d.%d (%02x.%02x.%02x.%02x)\n",
		firmware_version.major, firmware_version.minor,
		firmware_version.patch, firmware_version.reserved,
		firmware_version.major, firmware_version.minor,
		firmware_version.patch, firmware_version.reserved);
	crypto_ecc256_init();

	int is_init = authenticator_read_state(&STATE);

	device_set_status(CTAPHID_STATUS_IDLE);

	if (is_init) {
		printf1(TAG_STOR, "Auth state is initialized\n");
	} else {
		ctap_state_init();
		authenticator_write_state(&STATE);
	}

	crypto_derive_device_keys(STATE.key_salt, KEY_SALT_BYTES);

	if (ctap_client_pin_is_set()) {
		printf1(TAG_STOR, "attempts_left: %d\n", STATE.remaining_tries);
	} else {
		printf1(TAG_STOR, "pin not set.\n");
	}
	if (ctap_client_pin_is_locked()) {
		printf1(TAG_ERR, "DEVICE LOCKED!\n");
	}

	if (ctap_generate_rng(PIN_TOKEN, PIN_TOKEN_SIZE) != 1) {
		printf2(TAG_ERR, "Error, rng failed\n");
		exit(1);
	}

	ctap_client_pin_reset_key_agreement();
}

int ctap_make_auth_data(struct rpId *rp, uint8_t *rp_id_hash,
			uint8_t *rp_id_lookup, CborEncoder *map,
			uint8_t *auth_data_buf, uint32_t *len,
			CTAP_credInfo *credInfo, CTAP_extensions *extensions)
{
	CborEncoder cose_key;

	unsigned int auth_data_sz = sizeof(CTAP_authDataHeader);
	uint32_t count;
	CTAP_residentKey rk = {0x00};
	CTAP_authData *authData = (CTAP_authData *)auth_data_buf;

	uint8_t *cose_key_buf = auth_data_buf + sizeof(CTAP_authData);

	if ((sizeof(CTAP_authDataHeader)) > *len) {
		printf1(
		    TAG_ERR,
		    "assertion fail, auth_data_buf must be at least %d bytes\n",
		    sizeof(CTAP_authData) - sizeof(CTAP_attestHeader));
		exit(1);
	}

	memcpy(authData->head.rpIdHash, rp_id_hash, 32);

	count = ctap_auth_data_update_count(&authData->head);

	int but;

	but = ctap2_user_presence_test();
	if (CTAP2_ERR_PROCESSING == but) {
		authData->head.flags = (0 << 0); // User presence disabled
	} else {
		check_retr(but);
		authData->head.flags = (1 << 0); // User presence
	}

	device_set_status(CTAPHID_STATUS_PROCESSING);

	authData->head.flags |= (ctap_client_pin_is_set() << 2);

	if (credInfo != NULL) {
		// add attestedCredentialData
		authData->head.flags |= (1 << 6); // include attestation data

		cbor_encoder_init(&cose_key, cose_key_buf,
				  *len - sizeof(CTAP_authData), 0);

		attestation_read_aaguid(authData->attest.aaguid);
		authData->attest.credLenL = sizeof(CredentialId) & 0x00FF;
		authData->attest.credLenH =
		    (sizeof(CredentialId) & 0xFF00) >> 8;

		memset((uint8_t *)&authData->attest.id, 0,
		       sizeof(CredentialId));

		ctap_generate_rng(authData->attest.id.nonce,
				  CREDENTIAL_NONCE_SIZE);

		uint8_t alg =
		    credInfo->COSEAlgorithmIdentifier == COSE_ALG_EDDSA
			? CREDID_ALG_EDDSA
			: CREDID_ALG_ES256;

		uint8_t metadata[CREDENTIAL_METADATA_SIZE] = {0x00};
		metadata[CREDENTIAL_META_ALG_BYTE] = alg;
		metadata[CREDENTIAL_META_CRED_PROTECT_BYTE] =
		    extensions->cred_protect;
		metadata[CREDENTIAL_META_FLAGS_BYTE] =
		    (credInfo->rk & CREDENTIAL_META_IS_RK_BITMASK);

		ctap_xcrypt_buf(authData->attest.id.nonce, metadata,
				authData->attest.id.protected_metadata,
				CREDENTIAL_METADATA_SIZE);

		authData->attest.id.count = count;

		memmove(authData->attest.id.rp_id_lookup, rp_id_lookup,
			CREDENTIAL_TAG_SIZE);

		// Make a tag we can later check to make sure this is a token we
		// made
		ctap_make_auth_tag(authData->attest.id.rp_id_lookup,
				   authData->attest.id.nonce,
				   authData->attest.id.protected_metadata,
				   count, authData->attest.id.tag);

		// resident key
		if (credInfo->rk) {
			// Check for space
			if (STATE.rk_stored >= ctap_max_number_of_rks()) {
				return CTAP2_ERR_KEY_STORE_FULL;
			}
			// Fill credential
			memmove(&rk.id, &authData->attest.id,
				sizeof(CredentialId));
			// Fill userEntity
			memmove(&rk.user, &credInfo->user,
				sizeof(CTAP_userEntity));
			// Fill RPID-hash
			memmove(rk.rp.rp_id_hash, rp_id_hash, 32);
			// Fill ID-lookup mac
			derive_user_id_lookup(rk.user.id, rk.user.id_size,
					      rk.user_id_lookup);

			// Copy rpId to RK, but it could be cropped.
			truncate_rpid(rk.rp.rp_id, &rk.rp.rp_id_size, rp->id,
				      rp->size);

			// Fill RK nonce
			ctap_generate_rng(rk.rk_nonce, CREDENTIAL_NONCE_SIZE);
			printf1(TAG_MC, "rk.rk_nonce\n");
			dump_hex1(TAG_MC, rk.rk_nonce, CREDENTIAL_NONCE_SIZE);

			// Encrypting sensitive data (userEntity and rpEntity)
			ctap_xcrypt_buf(rk.rk_nonce, &rk.user, &rk.user,
					sizeof(CTAP_userEntity) +
					    sizeof(rpEntity));

			// Make hmac over the reset of the rk, that we can later
			// verify
			ctap_compute_mac(&rk.user, RK_HMAC_SIZE, rk.rk_tag,
					 CREDENTIAL_TAG_SIZE);

			int ret = ctap_overwrite_rk(&rk);
			if (ret < 0) {
				return CTAP1_ERR_OTHER;
			}
		}

		printf1(TAG_GREEN, "MADE credId:\n");
		dump_hex1(TAG_GREEN, (uint8_t *)&authData->attest.id,
			  sizeof(CredentialId));

		cose_key_generate(&cose_key, (uint8_t *)&authData->attest.id,
				  sizeof(CredentialId),
				  credInfo->publicKeyCredentialType,
				  credInfo->COSEAlgorithmIdentifier);

		auth_data_sz =
		    sizeof(CTAP_authData) +
		    cbor_encoder_get_buffer_size(&cose_key, cose_key_buf);
	}

	*len = auth_data_sz;
	return 0;
}

void ctap_make_auth_tag(uint8_t *rp_id_lookup, uint8_t *nonce,
			uint8_t *metadata, uint32_t count, uint8_t *tag)
{
	uint8_t hashbuf[32];
	memset(hashbuf, 0, sizeof(hashbuf));

	const uint8_t *mac_key = crypto_get_key_mac();

	crypto_sha256_hmac_init(mac_key, CRYPTO_KEY_LEN);
	crypto_sha256_update(rp_id_lookup, CREDENTIAL_TAG_SIZE);
	crypto_sha256_update(nonce, CREDENTIAL_NONCE_SIZE);
	crypto_sha256_update(metadata, CREDENTIAL_METADATA_SIZE);
	crypto_sha256_update((uint8_t *)&count, 4);
	crypto_sha256_hmac_final(mac_key, CRYPTO_KEY_LEN, hashbuf);

	memmove(tag, hashbuf, CREDENTIAL_TAG_SIZE);
}

uint8_t ctap_request(uint8_t *pkt_raw, int length, CTAP_RESPONSE *resp)
{
	CborEncoder encoder;
	memset(&encoder, 0, sizeof(CborEncoder));
	uint8_t status = 0;
	uint8_t cmd = *pkt_raw;
	pkt_raw++;
	length--;

	uint8_t *buf = resp->data;

	cbor_encoder_init(&encoder, buf, resp->data_size, 0);

	printf1(TAG_CTAP, "cbor input structure: %d bytes\n", length);
	printf1(TAG_DUMP, "cbor req:\n");
	dump_hex1(TAG_DUMP, pkt_raw, length);

	switch (cmd) {
	case CTAP_MAKE_CREDENTIAL:
	case CTAP_GET_ASSERTION:
	case CTAP_CREDENTIAL_MANAGEMENT:
	case CTAP_CREDENTIAL_MANAGEMENT_PRE:
		if (ctap_client_pin_is_locked()) {
			status = CTAP2_ERR_PIN_BLOCKED;
			goto done;
		}
		if (ctap_client_pin_is_boot_locked()) {
			status = CTAP2_ERR_PIN_AUTH_BLOCKED;
			goto done;
		}
		break;
	}

	switch (cmd) {
	case CTAP_MAKE_CREDENTIAL:
		printf1(TAG_CTAP, "CTAP_MAKE_CREDENTIAL\n");
		timestamp();
		status = ctap_make_credential(&encoder, pkt_raw, length);
		printf1(TAG_TIME, "make_credential time: %d ms\n", timestamp());

		resp->length = cbor_encoder_get_buffer_size(&encoder, buf);
		dump_hex1(TAG_DUMP, buf, resp->length);

		break;
	case CTAP_GET_ASSERTION:
		printf1(TAG_CTAP, "CTAP_GET_ASSERTION\n");
		timestamp();
		status = ctap_get_assertion(&encoder, pkt_raw, length);
		printf1(TAG_TIME, "get_assertion time: %d ms\n", timestamp());

		resp->length = cbor_encoder_get_buffer_size(&encoder, buf);

		printf1(TAG_DUMP, "cbor [%d]:\n", resp->length);
		dump_hex1(TAG_DUMP, buf, resp->length);
		break;
	case CTAP_GET_INFO:
		printf1(TAG_CTAP, "CTAP_GET_INFO\n");
		status = ctap_get_info(&encoder);

		resp->length = cbor_encoder_get_buffer_size(&encoder, buf);

		dump_hex1(TAG_DUMP, buf, resp->length);

		break;
	case CTAP_CLIENT_PIN:
		printf1(TAG_CTAP, "CTAP_CLIENT_PIN\n");
		status = ctap_client_pin(&encoder, pkt_raw, length);

		resp->length = cbor_encoder_get_buffer_size(&encoder, buf);
		dump_hex1(TAG_DUMP, buf, resp->length);
		break;
	case CTAP_RESET:
		printf1(TAG_CTAP, "CTAP_RESET\n");
		status = ctap2_user_presence_test();
		if (status == CTAP1_ERR_SUCCESS) {
			ctap_reset();
		}
		break;
	case CTAP_GET_NEXT_ASSERTION:
		printf1(TAG_CTAP, "CTAP_NEXT_ASSERTION\n");
		if (getAssertionState.lastcmd == CTAP_GET_ASSERTION) {
			status = ctap_get_next_assertion(&encoder);
			resp->length =
			    cbor_encoder_get_buffer_size(&encoder, buf);
			dump_hex1(TAG_DUMP, buf, resp->length);
			if (status == 0) {
				cmd = CTAP_GET_ASSERTION; // allow for next
							  // assertion
			}
		} else {
			printf2(
			    TAG_ERR,
			    "unwanted GET_NEXT_ASSERTION.  lastcmd == 0x%02x\n",
			    getAssertionState.lastcmd);
			status = CTAP2_ERR_NOT_ALLOWED;
		}
		break;
	case CTAP_CREDENTIAL_MANAGEMENT:
	case CTAP_CREDENTIAL_MANAGEMENT_PRE:
		printf1(TAG_CTAP, "CTAP_CREDENTIAL_MANAGEMENT\n");
		status = ctap_credential_management(&encoder, pkt_raw, length);

		resp->length = cbor_encoder_get_buffer_size(&encoder, buf);

		dump_hex1(TAG_DUMP, buf, resp->length);
		break;

	case CTAP_SELECTION:
		printf1(TAG_CTAP, "CTAP_AUTHENTICATOR_SELECTION\n");
		status = ctap2_user_presence_test();
		if (status != CTAP1_ERR_SUCCESS) {
			status = CTAP2_ERR_USER_ACTION_TIMEOUT;
		}
		break;

	default:
		status = CTAP1_ERR_INVALID_COMMAND;
		printf2(TAG_ERR, "Error, invalid cmd: 0x%02x\n", cmd);
	}

done:
	device_set_status(CTAPHID_STATUS_IDLE);
	getAssertionState.lastcmd = cmd;

	if (status != CTAP1_ERR_SUCCESS) {
		resp->length = 0;
	}

	printf1(TAG_CTAP, "cbor output structure: %d bytes.  Return 0x%02x\n",
		resp->length, status);

	return status;
}

void ctap_response_init(CTAP_RESPONSE *resp)
{
	memset(resp, 0, sizeof(CTAP_RESPONSE));
	resp->data_size = CTAP_RESPONSE_BUFFER_SIZE;
}

int32_t ctap_restore_metadata_cose_alg(CredentialId *credential)
{

	uint8_t metadata[CREDENTIAL_METADATA_SIZE];

	ctap_xcrypt_buf(credential->nonce, credential->protected_metadata,
			metadata, CREDENTIAL_METADATA_SIZE);

	uint8_t alg = metadata[CREDENTIAL_META_ALG_BYTE];

	switch (alg) {
	default:
	case CREDID_ALG_ES256:
		return COSE_ALG_ES256;
	case CREDID_ALG_EDDSA:
		return COSE_ALG_EDDSA;
	}
}

// require load_key prior to this
// @data data to hash before signature, MUST have room to append clientDataHash
// for ED25519
// @clientDataHash for signature
// @tmp buffer for hash.  (can be same as data if data >= 32 bytes)
// @sigbuf OUT location to deposit signature (must be 64 bytes)
// @sigder OUT location to deposit der signature (must be 72 bytes)
// @return length of der signature
int ctap_sign_data(uint8_t *data, int datalen, uint8_t *clientDataHash,
		   uint8_t *hashbuf, uint8_t *sigbuf, uint8_t *sigder,
		   int32_t alg)
{
	// calculate attestation sig
	if (alg == COSE_ALG_EDDSA) {
		fido2_crypto_ed25519_sign(
		    data, datalen, clientDataHash, CLIENT_DATA_HASH_SIZE,
		    sigder); // not DER, just plain binary!
		return 64;
	} else {
		crypto_sha256_init();
		crypto_sha256_update(data, datalen);
		crypto_sha256_update(clientDataHash, CLIENT_DATA_HASH_SIZE);
		crypto_sha256_final(hashbuf);

		crypto_ecc256_sign(hashbuf, 32, sigbuf);
		return ctap_encode_der_sig(sigbuf, sigder);
	}
}

void ctap_state_init()
{
	// Set to 0xff instead of 0x00 to be easier on flash
	memset(&STATE, 0xff, sizeof(AuthenticatorState));
	// Fresh RNG for key
	ctap_generate_rng(STATE.key_salt, KEY_SALT_BYTES);

	STATE.is_initialized = INITIALIZED_MARKER;
	STATE.remaining_tries = PIN_LOCKOUT_ATTEMPTS;
	STATE.is_pin_set = 0;
	STATE.rk_stored = 0;
	STATE.data_version = STATE_VERSION;

	ctap_reset_rk();

	if (ctap_generate_rng(STATE.PIN_SALT, sizeof(STATE.PIN_SALT)) != 1) {
		printf2(TAG_ERR, "Error, ctap_generate_rng() failed\n");
		exit(1);
	}

	printf1(TAG_STOR, "Generated PIN SALT:\n");
	dump_hex1(TAG_STOR, STATE.PIN_SALT, sizeof STATE.PIN_SALT);
}

// Returns 1 if the mac matches the input data, otherwise zero.
// mac is supposed to be of size CREDENTIAL_TAG_SIZE
int ctap_verify_mac(const uint8_t *mac, const void *data, size_t data_len)
{
	uint8_t local_mac[16];
	ctap_compute_mac(data, data_len, local_mac, CREDENTIAL_TAG_SIZE);

	return memcmp(local_mac, mac, CREDENTIAL_TAG_SIZE) == 0;
}

// Return 1 if rk still exists and is valid, 0 otherwise
int ctap_verify_rk_exists(const CredentialId *input_cred)
{
	CTAP_residentKey lookup_rk;

	int count = ctap_open_rk_file(input_cred->rp_id_lookup);
	if (count <= 0) {
		printf1(TAG_GREEN, "verify_rk_exists: no rk match\n");
		ctap_close_rk_file();
		return 0;
	}

	for (uint16_t i = 0; i < count; i++) {

		ctap_load_next_rk(&lookup_rk);

		// Compare RPID lookup
		if (memcmp(input_cred->rp_id_lookup, lookup_rk.id.rp_id_lookup,
			   CREDENTIAL_TAG_SIZE) != 0) {
			// Not the right RPID
			printf1(TAG_GREEN,
				"verify_rk_exists: wrong rpid (%d)\n", i);
			continue;
		}

		// Compare entire credentialID for full match
		if (!is_cred_id_matching_rk(input_cred, &lookup_rk)) {
			// Not the right credential
			printf1(TAG_GREEN,
				"verify_rk_exists: not exact match (%d)\n", i);
			continue;
		}

		// Verify rk_tag, so the credential still is considered
		// valid No need to decrypt
		if (!ctap_verify_mac(lookup_rk.rk_tag, &lookup_rk.user,
				     RK_HMAC_SIZE)) {
			printf1(TAG_GREEN,
				"verify_rk_exists: failed rk_tag verification "
				"(%d)\n",
				i);
			continue;
		}

		printf1(TAG_GREEN, "verify_rk_exists: found match (%d)\n", i);

		ctap_close_rk_file();
		return 1;
	}
	printf1(TAG_GREEN, "verify_rk_exists: no rk match\n");
	ctap_close_rk_file();
	return 0;
}

// Encrypts/decrypts length bytes of data using AES256 in CTR-mode.
// Will use the meta_key.
// Needs a 16 byte IV, unique per plain-text (credential, rk etc.).
//
// Encrypt data by having un-encrypted data in *in, and get the encrypted data
// in *out.
// Decrypt data by having encrypted data in *in, and get the un-encrypted data
// in *out.
//
// *in and *out can be the same buffer to encrypt/decrypt in-places, but
// cannot be partly overlapping.
void ctap_xcrypt_buf(const uint8_t *iv, const void *in, void *out,
		     uint8_t length)
{
	const uint8_t *p_in = (const uint8_t *)in;
	uint8_t *p_out = (uint8_t *)out;

	const uint8_t *meta_key = crypto_get_key_meta();

	// Don't copy if it is the same buffer
	if (p_in != p_out) {
		memcpy(p_out, p_in, length);
	}

	crypto_aes256_ctr_xcrypt_buffer(meta_key, iv, p_out, length);
}

/*****************************************************************************/

// Computes the MAC over data, using the the already generated key for computing
// MACs
void ctap_compute_mac(const void *data, size_t data_len, uint8_t *mac,
		      size_t mac_len)
{
	const uint8_t *p = (const uint8_t *)data;
	const uint8_t *mac_key = crypto_get_key_mac();

	uint8_t buf[32] = {0x00};

	crypto_sha256_hmac_init(mac_key, CRYPTO_KEY_LEN);
	crypto_sha256_update(p, data_len);
	crypto_sha256_hmac_final(mac_key, CRYPTO_KEY_LEN, buf);

	memcpy(mac, buf, mac_len);
}

// Calculates ID-lookup mac
static void derive_user_id_lookup(const uint8_t *id, size_t size,
				  uint8_t *user_id_lookup)
{
	ctap_compute_mac(id, size, user_id_lookup, CREDENTIAL_TAG_SIZE);
}

// Returns 1 if it is a match
static int is_cred_id_matching_rk(const CredentialId *credId,
				  const CTAP_residentKey *rk)
{
	return (memcmp(credId, &rk->id, sizeof(CredentialId)) == 0);
}

// Follows the specified procedure to truncate an RP ID. Min lengths is 32
// bytes. See chapter 6.8.7 in CTAP 2.1.
static void truncate_rpid(uint8_t *stored_rpid, uint8_t *stored_len,
			  const uint8_t *rpid, size_t rpid_len)
{
	if (rpid_len <= CREDENTIAL_RP_ID_SIZE) {
		memcpy(stored_rpid, rpid, rpid_len);
		*stored_len = rpid_len;
		return;
	}

	size_t used = 0;
	const uint8_t *colon_position = memchr(rpid, ':', rpid_len);
	if (colon_position != NULL) {
		const size_t protocol_len = colon_position - rpid + 1;
		const size_t to_copy = protocol_len <= CREDENTIAL_RP_ID_SIZE
					   ? protocol_len
					   : CREDENTIAL_RP_ID_SIZE;
		memcpy(stored_rpid, rpid, to_copy);
		used += to_copy;
	}

	if (CREDENTIAL_RP_ID_SIZE - used < 3) {
		*stored_len = used;
		return;
	}

	// U+2026, horizontal ellipsis.
	stored_rpid[used++] = 0xe2;
	stored_rpid[used++] = 0x80;
	stored_rpid[used++] = 0xa6;

	const size_t to_copy = CREDENTIAL_RP_ID_SIZE - used;
	memcpy(&stored_rpid[used], rpid + rpid_len - to_copy, to_copy);
	assert(used + to_copy == CREDENTIAL_RP_ID_SIZE);
	*stored_len = CREDENTIAL_RP_ID_SIZE;
}
