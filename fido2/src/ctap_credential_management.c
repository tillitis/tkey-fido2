// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdint.h>

#include "ctap_client_pin.h"
#include "ctap_credential_management.h"
#include "ctap_errors.h"
#include "ctap_parse.h"
#include "device.h"
#include "log.h"
#include "storage.h"

#define CTAP_STATEFUL_TIMEOUT_MS 30000
#define MAX_UNIQUE_RP 50
#define COMPARE_LEN 8

typedef enum {
	RP_MODE_COUNT,
	RP_MODE_GET_NEXT
} rp_mode_t;

typedef enum {
	RK_MODE_COUNT,
	RK_MODE_GET_NEXT,
} rk_mode_t;

typedef struct {
	bool valid;
	uint8_t init_cmd;
	uint32_t timestamp;
	bool rk_valid;
	CTAP_residentKey rk;
	uint8_t seen[MAX_UNIQUE_RP][COMPARE_LEN];
	uint8_t seen_count;
	uint8_t rk_idx;
	uint8_t file_idx;
} credential_management_state_t;

static credential_management_state_t state = {0x00};
extern AuthenticatorState STATE;

static uint8_t cbor_encode_credential_metadata(CborEncoder *encoder);
static uint8_t cbor_encode_enumerate_credential(CborEncoder *encoder,
						int rk_count);
static uint8_t cbor_encode_enumerate_rp(CborEncoder *encoder, int rp_count);
static int check_state(uint8_t subCmd);
static void clear_state();
static int count_number_of_relying_parties(void);
static int count_rk(const uint8_t *rp_id_hash);
static uint8_t extract_cred_protect_from_metadata(CredentialId *credential);
static int get_next_rk(const uint8_t *rp_id_hash);
static int get_next_rp(void);
static void init_state(uint8_t cmd);
static uint8_t parse_credential_management_request(CTAP_credMgmt *CM,
						   uint8_t *request,
						   int length);
static uint8_t parse_credential_management_subcommandparams(CborValue *val,
							    CTAP_credMgmt *CM);
static int resident_key_is_valid(CTAP_residentKey *rk);
static int scan_rk(const uint8_t *rp_id_lookup, rk_mode_t mode);
static int scan_rp(rp_mode_t mode);
static int update_credential_user_info(CredentialId *id, CTAP_userEntity *user);
static uint8_t verify_pin_auth_for_credential_management(CTAP_credMgmt *CM);

uint8_t ctap_credential_management(CborEncoder *encoder, uint8_t *request,
				   int length)
{
	CTAP_credMgmt CM;

	int ret = parse_credential_management_request(&CM, request, length);
	if (ret != 0) {
		printf2(
		    TAG_ERR,
		    "Error, parse_credential_management_request() failed\n");
		return ret;
	}
	ret = verify_pin_auth_for_credential_management(&CM);
	check_retr(ret);

	// TODO: check parse for each subcommand and return
	// CTAP2_ERR_MISSING_PARAMETER

	switch (CM.subCommand) {

	case CM_SubCmd_getCredsMetadata:
		printf1(TAG_CM, "CM_SubCmd_getCredsMetadata\n");
		// TODO: verify number of keys stored by counting
		ret = cbor_encode_credential_metadata(encoder);
		check_ret(ret);
		break;

	case CM_SubCmd_enumerateRPsBegin:
		printf1(TAG_CM, "CM_SubCmd_enumerateRPsBegin\n");
		init_state(CM_SubCmd_enumerateRPsBegin);

		ret = count_number_of_relying_parties();
		printf1(TAG_CM, "Number of RP found %d\n", ret);
		if (ret <= 0) {
			clear_state();
			return CTAP2_ERR_NO_CREDENTIALS;
		}
		ret = cbor_encode_enumerate_rp(encoder, ret);
		check_ret(ret);
		break;

	case CM_SubCmd_enumerateRPsGetNextRP:
		printf1(TAG_CM, "CM_SubCmd_enumerateRPsGetNextRP\n");

		ret = check_state(CM_SubCmd_enumerateRPsGetNextRP);
		printf1(TAG_CM, "check_state (%d)\n", ret);
		if (ret < 0) {
			return CTAP2_ERR_NOT_ALLOWED;
		}

		ret = get_next_rp();
		printf1(TAG_CM, "get_next_rp (%d)\n", ret);
		if (ret < 0) {
			clear_state();
			return CTAP1_ERR_OTHER;
		}

		ret = cbor_encode_enumerate_rp(encoder, 0);
		check_ret(ret);
		break;

	case CM_SubCmd_enumerateCredentialsBegin:
		printf1(TAG_CM, "CM_SubCmd_enumerateCredentialsBegin\n");
		init_state(CM_SubCmd_enumerateCredentialsBegin);

		int count = count_rk(CM.subCommandParams.rpIdHash);
		if (count <= 0) {
			clear_state();
			return CTAP2_ERR_NO_CREDENTIALS;
		}

		ret = get_next_rk(CM.subCommandParams.rpIdHash);
		if (ret < 0) {
			clear_state();
			return CTAP2_ERR_NO_CREDENTIALS;
		}

		ret = cbor_encode_enumerate_credential(encoder, count);
		check_ret(ret);
		break;

	case CM_SubCmd_enumerateCredentialsGetNextCredential:
		printf1(TAG_CM,
			"CM_SubCmd_enumerateCredentialsGetNextCredential\n");

		ret = check_state(
		    CM_SubCmd_enumerateCredentialsGetNextCredential);
		printf1(TAG_CM, "check_state (%d)\n", ret);
		if (ret < 0) {
			return CTAP2_ERR_NOT_ALLOWED;
		}

		ret = get_next_rk(state.rk.rp.rp_id_hash);
		if (ret < 0) {
			clear_state();
			return CTAP1_ERR_OTHER;
		}

		ret = cbor_encode_enumerate_credential(encoder, 0);
		check_ret(ret);
		break;

	case CM_SubCmd_deleteCredential:
		printf1(TAG_CM, "CM_SubCmd_deleteCredential\n");

		ret = ctap_delete_rk(
		    &CM.subCommandParams.credentialDescriptor.credential.id);
		if (ret < 0) {
			printf1(TAG_CM, "No Rk by given credId\n");
			return CTAP2_ERR_NO_CREDENTIALS;
		}
		printf1(TAG_CM, "Deleted rk %d\n", ret);
		break;

	case CM_SubCmd_updateUserInformation:
		printf1(TAG_CM, "cm_subcmd_updateuserinformation\n");

		ret = update_credential_user_info(
		    &CM.subCommandParams.credentialDescriptor.credential.id,
		    &CM.subCommandParams.credentialDescriptor.credential.user);

		printf1(TAG_CM, "update_credential_user_info: %d\n", ret);
		return ret;
		break;

	default:
		printf2(TAG_ERR,
			"Error, invalid CTAP_CREDENTIAL_MANAGEMENT subCommand: "
			"0x%02x\n",
			CM.subCommand);
		return CTAP1_ERR_INVALID_COMMAND;
	}
	return 0;
}

// Static functions below.
static uint8_t cbor_encode_credential_metadata(CborEncoder *encoder)
{
	CborEncoder map;
	int ret = cbor_encoder_create_map(encoder, &map, 2);
	check_ret(ret);
	ret = cbor_encode_int(&map, 1);
	check_ret(ret);
	ret = cbor_encode_int(&map, STATE.rk_stored);
	check_ret(ret);
	ret = cbor_encode_int(&map, 2);
	check_ret(ret);
	int remaining_rks = ctap_max_number_of_rks() - STATE.rk_stored;
	ret = cbor_encode_int(&map, remaining_rks);
	check_ret(ret);
	ret = cbor_encoder_close_container(encoder, &map);
	check_ret(ret);
	return 0;
}

static uint8_t cbor_encode_enumerate_credential(CborEncoder *encoder,
						int rk_count)
{
	uint8_t cred_protect = extract_cred_protect_from_metadata(&state.rk.id);
	if (cred_protect == 0 || cred_protect > 3) {
		// Take default value of userVerificationOptional
		cred_protect = EXT_CRED_PROTECT_OPTIONAL;
	}

	int32_t cose_alg = ctap_restore_metadata_cose_alg(&state.rk.id);

	CborEncoder map;
	// rk_count should not be included for the GetNext subCommand
	size_t map_size = rk_count > 0 ? 5 : 4;
	int ret = cbor_encoder_create_map(encoder, &map, map_size);
	check_ret(ret);

	ret = cbor_encode_int(&map, 6);
	check_ret(ret);
	{
		ret = ctap_cbor_encode_user_entity(&map, &state.rk.user, 1);
		check_ret(ret);
	}

	ret = cbor_encode_int(&map, 7);
	check_ret(ret);
	{
		ret = ctap_cbor_encode_credential_descriptor(
		    &map, (struct Credential *)&state.rk, PUB_KEY_CRED_PUB_KEY);
		check_ret(ret);
	}

	ret = cbor_encode_int(&map, 8);
	check_ret(ret);
	{
		cose_key_generate(&map, (uint8_t *)&state.rk.id,
				  sizeof(CredentialId), PUB_KEY_CRED_PUB_KEY,
				  cose_alg);
	}

	if (rk_count > 0) {
		ret = cbor_encode_int(&map, 9);
		check_ret(ret);
		ret = cbor_encode_int(&map, rk_count);
		check_ret(ret);
	}

	ret = cbor_encode_int(&map, 0x0A);
	check_ret(ret);
	ret = cbor_encode_int(&map, cred_protect);
	check_ret(ret);

	ret = cbor_encoder_close_container(encoder, &map);
	check_ret(ret);
	return 0;
}

static uint8_t cbor_encode_enumerate_rp(CborEncoder *encoder, int rp_count)
{
	CborEncoder map;
	// rp_count should not be included in GetNext subCommand
	size_t map_size = rp_count > 0 ? 3 : 2;
	int ret = cbor_encoder_create_map(encoder, &map, map_size);
	check_ret(ret);
	ret = cbor_encode_int(&map, 3);
	check_ret(ret);
	{
		CborEncoder rp;
		ret = cbor_encoder_create_map(&map, &rp, 2);
		check_ret(ret);
		ret = cbor_encode_text_stringz(&rp, "id");
		check_ret(ret);
		if (state.rk.rp.rp_id_size <= sizeof(state.rk.rp.rp_id)) {
			ret = cbor_encode_text_string(
			    &rp, (const char *)state.rk.rp.rp_id,
			    state.rk.rp.rp_id_size);
		} else {
			ret = cbor_encode_text_string(&rp, "", 0);
		}
		check_ret(ret);
		ret = cbor_encode_text_stringz(&rp, "name");
		check_ret(ret);
		ret = cbor_encode_text_stringz(
		    &rp, (const char *)state.rk.user.name);
		check_ret(ret);
		ret = cbor_encoder_close_container(&map, &rp);
		check_ret(ret);
	}
	ret = cbor_encode_int(&map, 4);
	check_ret(ret);
	cbor_encode_byte_string(&map, state.rk.rp.rp_id_hash, 32);
	check_ret(ret);
	if (rp_count > 0) {
		ret = cbor_encode_int(&map, 5);
		check_ret(ret);
		ret = cbor_encode_int(&map, rp_count);
		check_ret(ret);
	}
	ret = cbor_encoder_close_container(encoder, &map);
	check_ret(ret);
	return 0;
}

// Returns zero if the subcommand is valid for current state, negative if not.
// Updates the timestamp of state.
static int check_state(uint8_t subCmd)
{
	// TODO: Should probably also check if the tokenWithPermissions is still
	// valid
	if (state.valid == true) {
		switch (subCmd) {
		case CM_SubCmd_enumerateRPsGetNextRP:
			if (state.init_cmd != CM_SubCmd_enumerateRPsBegin) {
				state.valid = false;
				clear_state();
				return -1;
			}
			break;

		case CM_SubCmd_enumerateCredentialsGetNextCredential:
			if (state.init_cmd !=
			    CM_SubCmd_enumerateCredentialsBegin) {
				state.valid = false;
				clear_state();
				return -1;
			}
			break;
		default:
			// unknown subcommand
			state.valid = false;
			clear_state();
			return -1;
			break;
		}

		uint32_t current_time = millis();

		if (current_time - state.timestamp > CTAP_STATEFUL_TIMEOUT_MS) {
			state.valid = false;
			clear_state();
			printf1(TAG_CM, "check_state: timeout\n");
			return -1;
		}

		state.timestamp = current_time;
		return 0;
	}
	return -1;
}

static void clear_state()
{
	memset(&state, 0x00, sizeof(state));
}

static int count_number_of_relying_parties(void)
{
	// reset iterator state before full scan
	state.file_idx = 0;
	state.rk_idx = 0;
	state.seen_count = 0;
	state.rk_valid = false;

	int count = scan_rp(RP_MODE_COUNT);

	return count;
}

static int count_rk(const uint8_t *rp_id_hash)
{
	state.rk_idx = 0;

	uint8_t rp_id_lookup[16];
	ctap_compute_mac(rp_id_hash, 32, rp_id_lookup, CREDENTIAL_TAG_SIZE);
	return scan_rk(rp_id_lookup, RK_MODE_COUNT);
}

static uint8_t extract_cred_protect_from_metadata(CredentialId *credential)
{
	uint8_t metadata[CREDENTIAL_METADATA_SIZE];
	ctap_xcrypt_buf(credential->nonce, credential->protected_metadata,
			metadata, CREDENTIAL_METADATA_SIZE);

	return metadata[CREDENTIAL_META_CRED_PROTECT_BYTE];
}

static int get_next_rk(const uint8_t *rp_id_hash)
{
	uint8_t rp_id_lookup[16];
	ctap_compute_mac(rp_id_hash, 32, rp_id_lookup, CREDENTIAL_TAG_SIZE);
	return scan_rk(rp_id_lookup, RK_MODE_GET_NEXT);
}

static int get_next_rp(void)
{
	return scan_rp(RP_MODE_GET_NEXT);
}

static void init_state(uint8_t cmd)
{
	clear_state();
	state.valid = true;
	state.timestamp = millis();
	state.init_cmd = cmd;
	printf1(TAG_CM, "State %d %d %d\n", state.valid, state.timestamp,
		state.init_cmd);
}

static uint8_t parse_credential_management_request(CTAP_credMgmt *CM,
						   uint8_t *request, int length)
{
	int ret;
	unsigned int i;
	int key;
	size_t map_length;
	CborParser parser;
	CborValue it, map;

	memset(CM, 0, sizeof(CTAP_credMgmt));
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

	printf1(TAG_PARSE, "CM map has %d elements\n", map_length);

	for (i = 0; i < map_length; i++) {
		if (cbor_value_get_type(&map) != CborIntegerType) {
			printf2(TAG_ERR, "Error, expecting int for map key\n");
			return CTAP2_ERR_INVALID_CBOR;
		}
		ret = cbor_value_get_int_checked(&map, &key);
		check_ret(ret);

		ret = cbor_value_advance(&map);
		check_ret(ret);

		switch (key) {
		case CM_Cmd_subCommand:
			printf1(TAG_PARSE, "CM_Cmd_subCommand\n");
			if (cbor_value_get_type(&map) != CborIntegerType) {
				printf2(TAG_ERR,
					"Error, expecting int for map key\n");
				return CTAP2_ERR_INVALID_CBOR;
			}
			ret = cbor_value_get_int_checked(&map, &CM->subCommand);
			check_ret(ret);
			CM->hashed.subCommand = CM->subCommand;
			break;

		case CM_Cmd_subCommandParams:
			printf1(TAG_PARSE, "CM_Cmd_subCommandParams\n");
			ret = parse_credential_management_subcommandparams(&map,
									   CM);
			check_ret(ret);
			break;

		case CM_Cmd_pinUvAuthProtocol:
			printf1(TAG_PARSE, "CM_Cmd_pinUvAuthProtocol\n");
			if (cbor_value_get_type(&map) != CborIntegerType) {
				printf2(TAG_ERR,
					"Error, expecting int for map key\n");
				return CTAP2_ERR_INVALID_CBOR;
			}
			ret =
			    cbor_value_get_int_checked(&map, &CM->pinProtocol);
			check_ret(ret);
			break;

		case CM_Cmd_pinUvAuthParam:
			printf1(TAG_PARSE, "CM_Cmd_pinUvAuthParam\n");
			ret = ctap_parse_fixed_length_byte_string(
			    &map, CM->pinAuth, PIN_UV_AUTH_PARAM_MAX_SIZE);
			check_retr(ret);
			CM->pinAuthPresent = 1;
			break;
		}
		ret = cbor_value_advance(&map);
		check_ret(ret);
	}

	return 0;
}

static uint8_t parse_credential_management_subcommandparams(CborValue *val,
							    CTAP_credMgmt *CM)
{
	size_t map_length;
	int key;
	int ret;
	unsigned int i;
	CborValue map;
	size_t sz = 32;

	if (cbor_value_get_type(val) != CborMapType) {
		printf2(TAG_ERR, "Error, expecting cbor map\n");
		return CTAP2_ERR_INVALID_CBOR;
	}

	ret = cbor_value_enter_container(val, &map);
	check_ret(ret);

	const uint8_t *start_byte = cbor_value_get_next_byte(&map) - 1;

	ret = cbor_value_get_map_length(val, &map_length);
	check_ret(ret);

	for (i = 0; i < map_length; i++) {
		if (cbor_value_get_type(&map) != CborIntegerType) {
			printf2(TAG_ERR,
				"Error, expecting integer type for map key, "
				"got %s\n",
				cbor_value_get_type_string(&map));
			return CTAP2_ERR_INVALID_CBOR;
		}
		ret = cbor_value_get_int(&map, &key);
		check_ret(ret);
		ret = cbor_value_advance(&map);
		check_ret(ret);
		switch (key) {
		case CM_SubCmdParam_rpIDHash:
			ret = cbor_value_copy_byte_string(
			    &map, CM->subCommandParams.rpIdHash, &sz, NULL);
			if (ret == CborErrorOutOfMemory) {
				printf2(TAG_ERR,
					"Error, map key is too large\n");
				return CTAP2_ERR_LIMIT_EXCEEDED;
			}
			check_ret(ret);
			break;

		case CM_SubCmdParam_credentialID:
			ret = ctap_parse_pubkey_credential_descriptor(
			    &map, &CM->subCommandParams.credentialDescriptor);
			check_ret(ret);
			break;

		case CM_SubCmdParam_user:
			ctap_parse_user_entity(
			    &CM->subCommandParams.credentialDescriptor
				 .credential.user,
			    &map);
			check_ret(ret);

			break;
		}
		ret = cbor_value_advance(&map);
		check_ret(ret);
	}

	const uint8_t *end_byte = cbor_value_get_next_byte(&map);

	uint32_t length = (uint32_t)(end_byte - start_byte);
	if (length > sizeof(CM->hashed.subCommandParamsCborCopy)) {
		return CTAP2_ERR_LIMIT_EXCEEDED;
	}
	// Copy the details that were hashed so they can be verified later.
	memmove(CM->hashed.subCommandParamsCborCopy, start_byte, length);
	CM->subCommandParamsCborSize = length;

	return 0;
}

// Return 1 if rk is valid, 0 if not.
static int resident_key_is_valid(CTAP_residentKey *rk)
{
	// TODO: this should check the hmac if it checks anything.
	// What should we do if a credentials is invalid?
	return (rk->id.count > 0 && rk->id.count != 0xffffffff);
}

static int scan_rk(const uint8_t *rp_id_lookup, rk_mode_t mode)
{

	int nbr_rk = ctap_open_rk_file(rp_id_lookup);
	if (nbr_rk < 0) {
		return -1;
	}

	int count = 0;

	while (state.rk_idx < nbr_rk) {

		ctap_load_rk(state.rk_idx++, &state.rk);

		if (!resident_key_is_valid(&state.rk)) {
			continue;
		}

		if (memcmp(rp_id_lookup, state.rk.id.rp_id_lookup,
			   CREDENTIAL_TAG_SIZE) != 0) {
			continue;
		}

		if (mode == RK_MODE_GET_NEXT) {

			ctap_close_rk_file();

			ctap_xcrypt_buf(
			    state.rk.rk_nonce, &state.rk.user, &state.rk.user,
			    sizeof(CTAP_userEntity) + sizeof(rpEntity));

			return 0;
		}

		count++;
	}

	ctap_close_rk_file();
	state.rk_idx = 0;

	return (mode == RK_MODE_COUNT) ? count : -1;
}

static int scan_rp(rp_mode_t mode)
{
	uint16_t count = 0;
	uint8_t file_idx_for_get_next = 0;
	uint8_t rk_idx_for_get_next = 0;
	CTAP_residentKey rk;

	while (state.file_idx < 16) {

		uint8_t tmp[1] = {state.file_idx << 4};
		int nbr_rk = ctap_open_rk_file(tmp);

		if (nbr_rk < 0) {
			state.file_idx++;
			continue;
		}

		while (state.rk_idx < nbr_rk) {

			ctap_load_rk(state.rk_idx++, &rk);

			if (!resident_key_is_valid(&rk)) {
				continue;
			}

			uint8_t *hash = rk.id.rp_id_lookup;

			int found = 0;
			for (uint8_t k = 0; k < state.seen_count; k++) {
				if (memcmp(state.seen[k], hash, COMPARE_LEN) ==
				    0) {
					found = 1;
					break;
				}
			}
			if (found) {
				continue;
			}

			// store seen
			if (state.seen_count < MAX_UNIQUE_RP) {
				memmove(state.seen[state.seen_count++], hash,
					COMPARE_LEN);
			} else {
				// No memory to store more rps
				continue;
			}

			if (mode == RP_MODE_GET_NEXT) {

				ctap_close_rk_file();

				memmove(&state.rk, &rk,
					sizeof(CTAP_residentKey));

				ctap_xcrypt_buf(state.rk.rk_nonce,
						&state.rk.user, &state.rk.user,
						sizeof(CTAP_userEntity) +
						    sizeof(rpEntity));

				return 0;
			}

			count++;

			// first RK capture (only needed once)
			if (!state.rk_valid) {
				memmove(&state.rk, &rk,
					sizeof(CTAP_residentKey));

				ctap_xcrypt_buf(state.rk.rk_nonce,
						&state.rk.user, &state.rk.user,
						sizeof(CTAP_userEntity) +
						    sizeof(rpEntity));

				file_idx_for_get_next = state.file_idx;
				rk_idx_for_get_next = state.rk_idx;

				state.rk_valid = true;
			}
		}

		ctap_close_rk_file();

		state.file_idx++;
		state.rk_idx = 0;
		state.seen_count = 0; // reset per file
	}

	state.file_idx = file_idx_for_get_next;
	state.rk_idx = rk_idx_for_get_next;

	return (mode == RP_MODE_COUNT) ? count : -1;
}

static int update_credential_user_info(CredentialId *id, CTAP_userEntity *user)
{
	printf1(TAG_CM, "update_user_info\n");
	int ret;

	// Find matching credential
	clear_state();
	while (1) {

		ret = scan_rk(id->rp_id_lookup, RK_MODE_GET_NEXT);
		if (ret < 0) {
			return CTAP2_ERR_NO_CREDENTIALS;
		}

		if (!memcmp(id->tag, state.rk.id.tag, CREDENTIAL_TAG_SIZE)) {
			printf1(TAG_CM, "update_user_info: credid found\n");
			break;
		}
	}

	// Update user info, if id is same
	if (memcmp(state.rk.user.id, user->id, state.rk.user.id_size)) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	memmove(state.rk.user.name, user->name, USER_NAME_LIMIT);
	memmove(state.rk.user.displayName, user->displayName,
		DISPLAY_NAME_LIMIT);

	// Encrypt sensitive data (userEntity and rpEntity) (new nonce)
	ctap_generate_rng(state.rk.rk_nonce, CREDENTIAL_NONCE_SIZE);
	ctap_xcrypt_buf(state.rk.rk_nonce, &state.rk.user, &state.rk.user,
			sizeof(CTAP_userEntity) + sizeof(rpEntity));

	// Make hmac over the reset of the rk, that we can later
	// verify
	ctap_compute_mac(&state.rk.user, RK_HMAC_SIZE, state.rk.rk_tag,
			 CREDENTIAL_TAG_SIZE);

	// overwrite in flash
	ret = ctap_overwrite_rk(&state.rk);
	clear_state();
	if (ret < 0) {
		return CTAP1_ERR_OTHER;
	}

	return 0;
}

static uint8_t verify_pin_auth_for_credential_management(CTAP_credMgmt *CM)
{
	if (CM->subCommand == CM_SubCmd_enumerateRPsGetNextRP ||
	    CM->subCommand == CM_SubCmd_enumerateCredentialsGetNextCredential) {
		// pinAuth is not required for these commands
		return 0;
	}

	int8_t ret =
	    ctap_client_pin_verify_auth_ex(CM->pinAuth, (uint8_t *)&CM->hashed,
					   CM->subCommandParamsCborSize + 1);

	if (ret == CTAP2_ERR_PIN_AUTH_INVALID) {
		ctap_client_pin_decrement_attempts();
		if (ctap_client_pin_is_boot_locked()) {
			return CTAP2_ERR_PIN_AUTH_BLOCKED;
		}
		return CTAP2_ERR_PIN_AUTH_INVALID;
	} else {
		ctap_client_pin_reset_attempts();
	}

	return ret;
}
