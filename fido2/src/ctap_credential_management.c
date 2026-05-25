// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "ctap.h"
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
	RK_MODE_COUNT,
	RK_MODE_GET_NEXT,
} rk_mode_t;

typedef struct {
	bool valid;
	uint8_t init_cmd;
	uint32_t timestamp;
	uint8_t rp_id_hash[32];
	uint8_t list_unique_rps[MAX_UNIQUE_RP]; // List of indices to unique
						// rps in file_idx
	uint8_t len_list_unique_rps;
	uint8_t rk_idx;
	uint8_t file_idx;
} credential_management_state_t;

static credential_management_state_t state = {0x00};
extern AuthenticatorState STATE;

static CtapStatus cbor_encode_credential_metadata(CborEncoder *encoder);
static CtapStatus
cbor_encode_enumerate_credential(CborEncoder *encoder,
				 CTAP_residentKey *enumerated_rk, int rk_count);
static CtapStatus cbor_encode_enumerate_rp(CborEncoder *encoder,
					   CTAP_residentKey *enumerated_rk,
					   int rp_count);
static int check_state(uint8_t subCmd);
static void clear_state();
static int get_count_unique_relying_parties(void);
static int count_rk(const uint8_t *rp_id_hash, CTAP_residentKey *out_rk);
static uint8_t extract_cred_protect_from_metadata(CredentialId *credential);
static int get_next_rk(const uint8_t *rp_id_hash, CTAP_residentKey *out_rk);
static int get_next_unique_rp(CTAP_residentKey *out_rk);
static void init_state(uint8_t cmd);
static CtapStatus parse_credential_management_request(CTAP_credMgmt *CM,
						      uint8_t *request,
						      int length);
static CtapStatus
parse_credential_management_subcommandparams(CborValue *val, CTAP_credMgmt *CM);
static int resident_key_is_valid(CTAP_residentKey *rk);
static int scan_rk(const uint8_t *rp_id_lookup, rk_mode_t mode,
		   CTAP_residentKey *out_rk);
static int scan_file_unique_rp(uint8_t file_idx, uint8_t *out_list_len,
			       uint8_t *out_list_unique_rps);
static int scan_files_unique_rp(uint8_t *out_file_idx, uint8_t *out_list_len,
				uint8_t out_list_unique_rps[MAX_UNIQUE_RP]);
static CtapStatus update_credential_user_info(CredentialId *id,
					      CTAP_userEntity *user,
					      CTAP_residentKey *rk_buf);
static CtapStatus verify_pin_auth_for_credential_management(CTAP_credMgmt *CM);

CtapStatus ctap_credential_management(CborEncoder *encoder, uint8_t *request,
				      int length)
{
	int ret;
	int count = 0;
	CtapStatus ctap_ret;
	CTAP_credMgmt CM;
	CTAP_residentKey enumerated_rk = {0x00};

	ctap_ret = parse_credential_management_request(&CM, request, length);
	if (ctap_ret.value != CTAP2_OK) {
		printf2(
		    TAG_ERR,
		    "Error, parse_credential_management_request() failed\n");
		return ctap_ret;
	}

	ctap_ret = verify_pin_auth_for_credential_management(&CM);
	ctap_check_retr(ctap_ret);

	switch (CM.subCommand) {
	case CM_SubCmd_getCredsMetadata:
		printf1(TAG_CM, "CM_SubCmd_getCredsMetadata\n");
		ctap_ret = cbor_encode_credential_metadata(encoder);
		ctap_check_retr(ctap_ret);
		break;

	case CM_SubCmd_enumerateRPsBegin:
		printf1(TAG_CM, "CM_SubCmd_enumerateRPsBegin\n");
		init_state(CM_SubCmd_enumerateRPsBegin);

		count = get_count_unique_relying_parties();
		printf1(TAG_CM, "Number of RP found %d\n", count);
		if (count <= 0) {
			clear_state();
			return (CtapStatus){CTAP2_ERR_NO_CREDENTIALS};
		}

		ret = get_next_unique_rp(&enumerated_rk);
		if (ret < 0) {
			clear_state();
			return (CtapStatus){CTAP2_ERR_NOT_ALLOWED};
		}

		ctap_ret =
		    cbor_encode_enumerate_rp(encoder, &enumerated_rk, count);
		ctap_check_retr(ctap_ret);
		break;

	case CM_SubCmd_enumerateRPsGetNextRP:
		printf1(TAG_CM, "CM_SubCmd_enumerateRPsGetNextRP\n");

		ret = check_state(CM_SubCmd_enumerateRPsGetNextRP);
		printf1(TAG_CM, "check_state (%d)\n", ret);
		if (ret < 0) {
			return (CtapStatus){CTAP2_ERR_NOT_ALLOWED};
		}

		ret = get_next_unique_rp(&enumerated_rk);
		printf1(TAG_CM, "get_next_unique_rp (%d)\n", ret);

		if (ret < 0) {
			clear_state();
			return (CtapStatus){CTAP2_ERR_NOT_ALLOWED};
		}

		ctap_ret = cbor_encode_enumerate_rp(encoder, &enumerated_rk, 0);
		ctap_check_retr(ctap_ret);
		break;

	case CM_SubCmd_enumerateCredentialsBegin:
		printf1(TAG_CM, "CM_SubCmd_enumerateCredentialsBegin\n");
		init_state(CM_SubCmd_enumerateCredentialsBegin);

		if (!CM.subCommandParams.rpIdHash_present) {
			return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
		}

		// Store RP ID hash for GetNext request
		memcpy(state.rp_id_hash, CM.subCommandParams.rpIdHash, 32);

		count = count_rk(state.rp_id_hash, &enumerated_rk);
		if (count <= 0) {
			clear_state();
			return (CtapStatus){CTAP2_ERR_NO_CREDENTIALS};
		}

		ret = get_next_rk(state.rp_id_hash, &enumerated_rk);
		if (ret < 0) {
			clear_state();
			return (CtapStatus){CTAP2_ERR_NO_CREDENTIALS};
		}

		ctap_ret = cbor_encode_enumerate_credential(
		    encoder, &enumerated_rk, count);
		ctap_check_retr(ctap_ret);
		break;

	case CM_SubCmd_enumerateCredentialsGetNextCredential:
		printf1(TAG_CM,
			"CM_SubCmd_enumerateCredentialsGetNextCredential\n");

		ret = check_state(
		    CM_SubCmd_enumerateCredentialsGetNextCredential);
		printf1(TAG_CM, "check_state (%d)\n", ret);
		if (ret < 0) {
			return (CtapStatus){CTAP2_ERR_NOT_ALLOWED};
		}

		ret = get_next_rk(state.rp_id_hash, &enumerated_rk);
		if (ret < 0) {
			clear_state();
			return (CtapStatus){CTAP1_ERR_OTHER};
		}

		ctap_ret = cbor_encode_enumerate_credential(encoder,
							    &enumerated_rk, 0);
		ctap_check_retr(ctap_ret);
		break;

	case CM_SubCmd_deleteCredential:
		printf1(TAG_CM, "CM_SubCmd_deleteCredential\n");

		if (!CM.subCommandParams.credentialId_present) {
			return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
		}

		ret = ctap_delete_rk(
		    &CM.subCommandParams.credentialDescriptor.credential.id);
		if (ret < 0) {
			printf1(TAG_CM, "No Rk by given credId\n");
			return (CtapStatus){CTAP2_ERR_NO_CREDENTIALS};
		}
		printf1(TAG_CM, "Deleted rk %d\n", ret);
		break;

	case CM_SubCmd_updateUserInformation:
		printf1(TAG_CM, "cm_subcmd_updateuserinformation\n");

		if (!CM.subCommandParams.credentialId_present ||
		    !CM.subCommandParams.credentialUser_present) {
			return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
		}

		ctap_ret = update_credential_user_info(
		    &CM.subCommandParams.credentialDescriptor.credential.id,
		    &CM.subCommandParams.credentialDescriptor.credential.user,
		    &enumerated_rk);

		printf1(TAG_CM, "update_credential_user_info: %d\n",
			ctap_ret.value);
		return ctap_ret;
		break;

	default:
		printf2(TAG_ERR,
			"Error, invalid CTAP_CREDENTIAL_MANAGEMENT subCommand: "
			"0x%02x\n",
			CM.subCommand);
		return (CtapStatus){CTAP1_ERR_INVALID_COMMAND};
	}
	return (CtapStatus){CTAP2_OK};
}

// Static functions below.
static CtapStatus cbor_encode_credential_metadata(CborEncoder *encoder)
{
	CborEncoder map;
	CborError cbor_ret;

	cbor_ret = cbor_encoder_create_map(encoder, &map, 2);
	cbor_check_ret(cbor_ret);
	cbor_ret = cbor_encode_int(&map, 1);
	cbor_check_ret(cbor_ret);
	cbor_ret = cbor_encode_int(&map, STATE.rk_stored);
	cbor_check_ret(cbor_ret);
	cbor_ret = cbor_encode_int(&map, 2);
	cbor_check_ret(cbor_ret);
	int remaining_rks = ctap_max_number_of_rks() - STATE.rk_stored;
	cbor_ret = cbor_encode_int(&map, remaining_rks);
	cbor_check_ret(cbor_ret);
	cbor_ret = cbor_encoder_close_container(encoder, &map);
	cbor_check_ret(cbor_ret);

	return (CtapStatus){CTAP2_OK};
}

static CtapStatus
cbor_encode_enumerate_credential(CborEncoder *encoder,
				 CTAP_residentKey *enumerated_rk, int rk_count)
{
	CborError cbor_ret;
	CtapStatus ctap_ret;

	uint8_t cred_protect =
	    extract_cred_protect_from_metadata(&enumerated_rk->id);
	if (cred_protect == 0 || cred_protect > 3) {
		// Take default value of userVerificationOptional
		cred_protect = EXT_CRED_PROTECT_OPTIONAL;
	}

	int32_t cose_alg = ctap_restore_metadata_cose_alg(&enumerated_rk->id);

	CborEncoder map;
	// rk_count should not be included for the GetNext subCommand
	size_t map_size = rk_count > 0 ? 5 : 4;
	cbor_ret = cbor_encoder_create_map(encoder, &map, map_size);
	cbor_check_ret(cbor_ret);

	cbor_ret = cbor_encode_int(&map, 6);
	cbor_check_ret(cbor_ret);
	{
		ctap_ret =
		    ctap_cbor_encode_user_entity(&map, &enumerated_rk->user, 1);
		ctap_check_retr(ctap_ret);
	}

	cbor_ret = cbor_encode_int(&map, 7);
	cbor_check_ret(cbor_ret);
	{
		ctap_ret = ctap_cbor_encode_credential_descriptor(
		    &map, (struct Credential *)enumerated_rk,
		    PUB_KEY_CRED_PUB_KEY);
		ctap_check_retr(ctap_ret);
	}

	cbor_ret = cbor_encode_int(&map, 8);
	cbor_check_ret(cbor_ret);
	{
		// TODO Check return value here?
		cose_key_generate(&map, (uint8_t *)&enumerated_rk->id,
				  sizeof(CredentialId), PUB_KEY_CRED_PUB_KEY,
				  cose_alg);
	}

	if (rk_count > 0) {
		cbor_ret = cbor_encode_int(&map, 9);
		cbor_check_ret(cbor_ret);
		cbor_ret = cbor_encode_int(&map, rk_count);
		cbor_check_ret(cbor_ret);
	}

	cbor_ret = cbor_encode_int(&map, 0x0A);
	cbor_check_ret(cbor_ret);
	cbor_ret = cbor_encode_int(&map, cred_protect);
	cbor_check_ret(cbor_ret);

	cbor_ret = cbor_encoder_close_container(encoder, &map);
	cbor_check_ret(cbor_ret);

	return (CtapStatus){CTAP2_OK};
}

static CtapStatus cbor_encode_enumerate_rp(CborEncoder *encoder,
					   CTAP_residentKey *enumerated_rk,
					   int rp_count)
{
	CborEncoder map;
	// rp_count should not be included in GetNext subCommand
	size_t map_size = rp_count > 0 ? 3 : 2;
	CborError cbor_ret;

	cbor_ret = cbor_encoder_create_map(encoder, &map, map_size);
	cbor_check_ret(cbor_ret);
	cbor_ret = cbor_encode_int(&map, 3);
	cbor_check_ret(cbor_ret);
	{
		CborEncoder rp;
		cbor_ret = cbor_encoder_create_map(&map, &rp, 2);
		cbor_check_ret(cbor_ret);
		cbor_ret = cbor_encode_text_stringz(&rp, "id");
		cbor_check_ret(cbor_ret);
		if (enumerated_rk->rp.rp_id_size <=
		    sizeof(enumerated_rk->rp.rp_id)) {
			cbor_ret = cbor_encode_text_string(
			    &rp, (const char *)enumerated_rk->rp.rp_id,
			    enumerated_rk->rp.rp_id_size);
		} else {
			cbor_ret = cbor_encode_text_string(&rp, "", 0);
		}
		cbor_check_ret(cbor_ret);
		cbor_ret = cbor_encode_text_stringz(&rp, "name");
		cbor_check_ret(cbor_ret);
		cbor_ret = cbor_encode_text_stringz(
		    &rp, (const char *)enumerated_rk->user.name);
		cbor_check_ret(cbor_ret);
		cbor_ret = cbor_encoder_close_container(&map, &rp);
		cbor_check_ret(cbor_ret);
	}
	cbor_ret = cbor_encode_int(&map, 4);
	cbor_check_ret(cbor_ret);
	cbor_encode_byte_string(&map, enumerated_rk->rp.rp_id_hash, 32);
	cbor_check_ret(cbor_ret);
	if (rp_count > 0) {
		cbor_ret = cbor_encode_int(&map, 5);
		cbor_check_ret(cbor_ret);
		cbor_ret = cbor_encode_int(&map, rp_count);
		cbor_check_ret(cbor_ret);
	}
	cbor_ret = cbor_encoder_close_container(encoder, &map);
	cbor_check_ret(cbor_ret);

	return (CtapStatus){CTAP2_OK};
}

// Returns zero if the subcommand is valid for current state, negative if not.
// Updates the timestamp of state.
static int check_state(uint8_t subCmd)
{
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

static int get_count_unique_relying_parties(void)
{
	// Reset global state
	state.rk_idx = 0;
	state.file_idx = 0;
	state.len_list_unique_rps = 0;

	return scan_files_unique_rp(&state.file_idx, &state.len_list_unique_rps,
				    state.list_unique_rps);
}

static int count_rk(const uint8_t *rp_id_hash, CTAP_residentKey *out_rk)
{
	state.rk_idx = 0;

	uint8_t rp_id_lookup[16];
	ctap_compute_mac(rp_id_hash, 32, rp_id_lookup, CREDENTIAL_TAG_SIZE);
	return scan_rk(rp_id_lookup, RK_MODE_COUNT, out_rk);
}

static uint8_t extract_cred_protect_from_metadata(CredentialId *credential)
{
	uint8_t metadata[CREDENTIAL_METADATA_SIZE];
	ctap_xcrypt_buf(credential->nonce, credential->protected_metadata,
			metadata, CREDENTIAL_METADATA_SIZE);

	return metadata[CREDENTIAL_META_CRED_PROTECT_BYTE];
}

static int get_next_rk(const uint8_t *rp_id_hash, CTAP_residentKey *out_rk)
{
	uint8_t rp_id_lookup[16];
	ctap_compute_mac(rp_id_hash, 32, rp_id_lookup, CREDENTIAL_TAG_SIZE);
	return scan_rk(rp_id_lookup, RK_MODE_GET_NEXT, out_rk);
}

// returns next rp in line, continues to scan next file if EOF.
// Returns -1 when unique rps are exhausted
static int get_next_unique_rp(CTAP_residentKey *out_rk)
{

	printf1(TAG_CM, "get_next_flash %d %d\n", state.rk_idx,
		state.len_list_unique_rps);

	if (state.rk_idx >= state.len_list_unique_rps) {
		// End of file
		state.file_idx++;
		state.rk_idx = 0;
		state.len_list_unique_rps = 0;

		while (state.file_idx < MAX_RK_FILES) {
			int ret = scan_file_unique_rp(
			    state.file_idx, &state.len_list_unique_rps,
			    state.list_unique_rps);

			// No RP, check next file
			if (ret < 0 || state.len_list_unique_rps == 0) {
				state.file_idx++;
				continue;
			}

			break;
		}
	}

	// Nothing more to read
	if (state.len_list_unique_rps == 0) {
		return -1;
	}

	uint8_t tmp[1] = {state.file_idx << 4};
	int nbr_rk = ctap_open_rk_file(tmp);

	if (nbr_rk <= 0) {
		ctap_close_rk_file();
		return -1;
	}

	ctap_load_rk(state.list_unique_rps[state.rk_idx], out_rk);

	ctap_xcrypt_buf(out_rk->rk_nonce, &out_rk->user, &out_rk->user,
			sizeof(CTAP_userEntity) + sizeof(rpEntity));

	state.rk_idx++;
	ctap_close_rk_file();
	return 0;
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

static CtapStatus parse_credential_management_request(CTAP_credMgmt *CM,
						      uint8_t *request,
						      int length)
{
	CborError cbor_ret;
	CtapStatus ctap_ret;
	unsigned int i;
	int key;
	size_t map_length;
	CborParser parser;
	CborValue it, map;

	memset(CM, 0, sizeof(CTAP_credMgmt));
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

	printf1(TAG_PARSE, "CM map has %d elements\n", map_length);

	for (i = 0; i < map_length; i++) {
		if (cbor_value_get_type(&map) != CborIntegerType) {
			printf2(TAG_ERR, "Error, expecting int for map key\n");
			return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
		}
		cbor_ret = cbor_value_get_int_checked(&map, &key);
		cbor_check_ret(cbor_ret);

		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);

		switch (key) {
		case CM_Cmd_subCommand:
			printf1(TAG_PARSE, "CM_Cmd_subCommand\n");
			if (cbor_value_get_type(&map) != CborIntegerType) {
				printf2(TAG_ERR,
					"Error, expecting int for map key\n");
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}
			cbor_ret =
			    cbor_value_get_int_checked(&map, &CM->subCommand);
			cbor_check_ret(cbor_ret);
			CM->hashed.subCommand = CM->subCommand;
			break;

		case CM_Cmd_subCommandParams:
			printf1(TAG_PARSE, "CM_Cmd_subCommandParams\n");
			ctap_ret = parse_credential_management_subcommandparams(
			    &map, CM);
			ctap_check_retr(ctap_ret);
			break;

		case CM_Cmd_pinUvAuthProtocol:
			printf1(TAG_PARSE, "CM_Cmd_pinUvAuthProtocol\n");
			if (cbor_value_get_type(&map) != CborIntegerType) {
				printf2(TAG_ERR,
					"Error, expecting int for map key\n");
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}
			cbor_ret =
			    cbor_value_get_int_checked(&map, &CM->pinProtocol);
			cbor_check_ret(cbor_ret);
			break;

		case CM_Cmd_pinUvAuthParam:
			printf1(TAG_PARSE, "CM_Cmd_pinUvAuthParam\n");
			ctap_ret = ctap_parse_fixed_length_byte_string(
			    &map, CM->pinUvAuthParam,
			    PIN_UV_AUTH_PARAM_MAX_SIZE);
			ctap_check_retr(ctap_ret);
			CM->pinUvAuthParam_present = 1;
			break;
		}
		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);
	}

	return (CtapStatus){CTAP2_OK};
}

static CtapStatus
parse_credential_management_subcommandparams(CborValue *val, CTAP_credMgmt *CM)
{
	size_t map_length;
	int key;
	CborError cbor_ret;
	CtapStatus ctap_ret;
	unsigned int i;
	CborValue map;
	size_t sz = 32;

	if (cbor_value_get_type(val) != CborMapType) {
		printf2(TAG_ERR, "Error, expecting cbor map\n");
		return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
	}

	cbor_ret = cbor_value_enter_container(val, &map);
	cbor_check_ret(cbor_ret);

	const uint8_t *start_byte = cbor_value_get_next_byte(&map) - 1;

	cbor_ret = cbor_value_get_map_length(val, &map_length);
	cbor_check_ret(cbor_ret);

	for (i = 0; i < map_length; i++) {
		if (cbor_value_get_type(&map) != CborIntegerType) {
			printf2(TAG_ERR,
				"Error, expecting integer type for map key, "
				"got %s\n",
				cbor_value_get_type_string(&map));
			return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
		}
		cbor_ret = cbor_value_get_int(&map, &key);
		cbor_check_ret(cbor_ret);
		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);
		switch (key) {
		case CM_SubCmdParam_rpIDHash:
			cbor_ret = cbor_value_copy_byte_string(
			    &map, CM->subCommandParams.rpIdHash, &sz, NULL);
			if (cbor_ret == CborErrorOutOfMemory) {
				printf2(TAG_ERR,
					"Error, map key is too large\n");
				return (CtapStatus){CTAP2_ERR_LIMIT_EXCEEDED};
			}
			cbor_check_ret(cbor_ret);
			CM->subCommandParams.rpIdHash_present = true;
			break;

		case CM_SubCmdParam_credentialID:
			ctap_ret = ctap_parse_pubkey_credential_descriptor(
			    &map, &CM->subCommandParams.credentialDescriptor);
			ctap_check_retr(ctap_ret);
			CM->subCommandParams.credentialId_present = true;
			break;

		case CM_SubCmdParam_user:
			ctap_ret = ctap_parse_user_entity(
			    &CM->subCommandParams.credentialDescriptor
				 .credential.user,
			    &map);
			ctap_check_retr(ctap_ret);
			CM->subCommandParams.credentialUser_present = true;
			break;
		}
		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);
	}

	const uint8_t *end_byte = cbor_value_get_next_byte(&map);

	uint32_t length = (uint32_t)(end_byte - start_byte);
	if (length > sizeof(CM->hashed.subCommandParamsCborCopy)) {
		return (CtapStatus){CTAP2_ERR_LIMIT_EXCEEDED};
	}
	// Copy the details that were hashed so they can be verified later.
	memmove(CM->hashed.subCommandParamsCborCopy, start_byte, length);
	CM->subCommandParamsCborSize = length;

	return (CtapStatus){CTAP2_OK};
}

// Return 1 if rk is valid, 0 if not.
static int resident_key_is_valid(CTAP_residentKey *rk)
{
	// TODO: this should check the hmac if it checks anything.
	// What should we do if a credentials is invalid?
	return (rk->id.count > 0 && rk->id.count != 0xffffffff);
}

static int scan_rk(const uint8_t *rp_id_lookup, rk_mode_t mode,
		   CTAP_residentKey *out_rk)
{

	int nbr_rk = ctap_open_rk_file(rp_id_lookup);
	if (nbr_rk < 0) {
		ctap_close_rk_file();
		return -1;
	}

	int count = 0;

	while (state.rk_idx < nbr_rk) {

		ctap_load_rk(state.rk_idx++, out_rk);

		if (!resident_key_is_valid(out_rk)) {
			continue;
		}

		if (memcmp(rp_id_lookup, out_rk->id.rp_id_lookup,
			   CREDENTIAL_TAG_SIZE) != 0) {
			continue;
		}

		if (mode == RK_MODE_GET_NEXT) {

			ctap_close_rk_file();

			ctap_xcrypt_buf(
			    out_rk->rk_nonce, &out_rk->user, &out_rk->user,
			    sizeof(CTAP_userEntity) + sizeof(rpEntity));

			return 0;
		}

		count++;
	}

	ctap_close_rk_file();
	state.rk_idx = 0;

	return (mode == RK_MODE_COUNT) ? count : -1;
}

// Scans a file, if any rks present, returns a list of the indices for unique
// rps and the length of the list.
static int scan_file_unique_rp(uint8_t file_idx, uint8_t *out_list_len,
			       uint8_t *out_list_unique_rps)
{
	CTAP_residentKey tmp_rk;
	uint8_t seen[MAX_UNIQUE_RP][COMPARE_LEN] = {0x00};
	uint8_t seen_count = 0;

	uint8_t tmp[1] = {file_idx << 4};
	int ret = ctap_open_rk_file(tmp);

	if (ret < 0) {
		*out_list_len = 0;
		ctap_close_rk_file();
		return -1;
	}

	size_t nbr_rk = (size_t)ret;
	size_t index = 0;

	while (index < nbr_rk) {

		ctap_load_rk(index, &tmp_rk);

		if (!resident_key_is_valid(&tmp_rk)) {
			index++;
			continue;
		}

		uint8_t *hash = tmp_rk.id.rp_id_lookup;

		int found = 0;
		for (uint8_t k = 0; k < seen_count; k++) {
			if (memcmp(seen[k], hash, COMPARE_LEN) == 0) {
				found = 1;
				printf1(TAG_CM,
					"scan_file_unique_rp: already found\n");
				break;
			}
		}
		if (found) {
			index++;
			continue;
		}

		// store unique rp
		if (seen_count < MAX_UNIQUE_RP) {
			memmove(seen[seen_count], hash, COMPARE_LEN);
			out_list_unique_rps[seen_count] = index;
			seen_count++;
			printf1(TAG_CM, "scan_file_unique_rp: store seen\n");
		} else {
			// No memory to store more rps, return what we have.
			printf1(TAG_ERR, "scan_file_unique_rp: memory full\n");
			break;
		}
		index++;
	}

	ctap_close_rk_file();
	*out_list_len = seen_count;

	printf1(TAG_CM, "scan_file_unique_rp: found %d\n", seen_count);
	return 0;
}

// Returns number of unique RPs in entire storage.
// If any, returns a list of unique rps from the first non-empty file
// (out_file_idx) and the length of the list.
static int scan_files_unique_rp(uint8_t *out_file_idx, uint8_t *out_list_len,
				uint8_t out_list_unique_rps[MAX_UNIQUE_RP])
{
	uint16_t rp_count = 0;
	bool first_rp_list_stored = false;

	for (uint8_t file_idx = 0; file_idx < MAX_RK_FILES; file_idx++) {
		uint8_t tmp_list_indices[MAX_UNIQUE_RP] = {0x00};
		uint8_t file_count = 0;
		int ret = scan_file_unique_rp(file_idx, &file_count,
					      tmp_list_indices);

		// No RP, continue
		if (ret < 0 || file_count == 0) {
			continue;
		}

		// store the first list returned globally
		if (!first_rp_list_stored) {
			printf1(TAG_CM,
				"scan_files_unique_rp: store first %d\n",
				file_idx);
			memcpy(out_list_unique_rps, tmp_list_indices,
			       file_count);
			*out_file_idx = file_idx;
			*out_list_len = file_count;
			first_rp_list_stored = true;
		}

		rp_count += file_count;
	}
	return rp_count;
}

static CtapStatus update_credential_user_info(CredentialId *id,
					      CTAP_userEntity *user,
					      CTAP_residentKey *rk_buf)
{
	printf1(TAG_CM, "update_user_info\n");
	int ret;

	// Find matching credential
	clear_state();
	while (1) {

		ret = scan_rk(id->rp_id_lookup, RK_MODE_GET_NEXT, rk_buf);
		if (ret < 0) {
			return (CtapStatus){CTAP2_ERR_NO_CREDENTIALS};
		}

		if (!memcmp(id->tag, rk_buf->id.tag, CREDENTIAL_TAG_SIZE)) {
			printf1(TAG_CM, "update_user_info: credid found\n");
			break;
		}
	}

	// Update user info, if id is same
	if (memcmp(rk_buf->user.id, user->id, rk_buf->user.id_size)) {
		return (CtapStatus){CTAP1_ERR_INVALID_PARAMETER};
	}

	memmove(rk_buf->user.name, user->name, USER_NAME_LIMIT);
	memmove(rk_buf->user.displayName, user->displayName,
		DISPLAY_NAME_LIMIT);

	// Encrypt sensitive data (userEntity and rpEntity) (new nonce)
	ctap_generate_rng(rk_buf->rk_nonce, CREDENTIAL_NONCE_SIZE);
	ctap_xcrypt_buf(rk_buf->rk_nonce, &rk_buf->user, &rk_buf->user,
			sizeof(CTAP_userEntity) + sizeof(rpEntity));

	// Make hmac over the reset of the rk, that we can later
	// verify
	ctap_compute_mac(&rk_buf->user, RK_HMAC_SIZE, rk_buf->rk_tag,
			 CREDENTIAL_TAG_SIZE);

	// overwrite in flash
	ret = ctap_overwrite_rk(rk_buf);
	clear_state();
	if (ret < 0) {
		return (CtapStatus){CTAP1_ERR_OTHER};
	}

	return (CtapStatus){CTAP2_OK};
}

static CtapStatus verify_pin_auth_for_credential_management(CTAP_credMgmt *CM)
{
	if (CM->subCommand == CM_SubCmd_enumerateRPsGetNextRP ||
	    CM->subCommand == CM_SubCmd_enumerateCredentialsGetNextCredential) {
		// pinUvAuthParam is not required for these commands
		return (CtapStatus){CTAP2_OK};
	}

	if (!CM->pinUvAuthParam_present) {
		return (CtapStatus){CTAP2_ERR_PUAT_REQUIRED};
	}

	if (CM->pinProtocol != 1 && CM->pinProtocol != 2) {
		return (CtapStatus){CTAP1_ERR_INVALID_PARAMETER};
	}

	CtapStatus ctap_ret = ctap_client_pin_verify_auth_ex(
	    CM->pinUvAuthParam, (uint8_t *)&CM->hashed,
	    CM->subCommandParamsCborSize + 1, CM->pinProtocol);
	if (ctap_ret.value != CTAP2_OK) {
		return ctap_ret;
	}

	if (!ctap_client_pin_verify_permissions(
		CM->pinProtocol, CP_pinUvAuthToken_permissions_cm)) {
		return (CtapStatus){CTAP2_ERR_PIN_AUTH_INVALID};
	}

	if (CM->subCommand == CM_SubCmd_enumerateRPsBegin) {
		if (ctap_client_pin_permissions_rp_id_present(
			CM->pinProtocol)) {
			return (CtapStatus){CTAP2_ERR_PIN_AUTH_INVALID};
		}
	} else {
		if (!ctap_client_pin_verify_permissions_rp_id(
			CM->pinProtocol, CM->subCommandParams.rpIdHash)) {
			return (CtapStatus){CTAP2_ERR_PIN_AUTH_INVALID};
		}
	}

	return (CtapStatus){CTAP2_OK};
}
