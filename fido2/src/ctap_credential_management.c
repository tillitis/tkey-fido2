#include <stdint.h>

#include "ctap.h"
#include "ctap_client_pin.h"
#include "ctap_credential_management.h"
#include "ctap_errors.h"
#include "ctap_parse.h"
#include "ctap_reset.h"
#include "device.h"
#include "log.h"
#include "storage.h"

extern AuthenticatorState STATE;

static uint8_t cbor_encode_credential_metadata(CborEncoder *encoder);
static uint8_t cbor_encode_relying_party(CborEncoder *encoder, int rk_ind,
					 int rp_count);
static uint8_t cbor_encode_resident_key(CborEncoder *encoder, int rk_ind,
					int rk_count);
static uint8_t extract_cred_protect_from_metadata(CredentialId *credential);
static uint8_t parse_credential_management_request(CTAP_credMgmt *CM,
						   uint8_t *request,
						   int length);
static uint8_t parse_credential_management_subcommandparams(CborValue *val,
							    CTAP_credMgmt *CM);
static int resident_key_is_valid(CTAP_residentKey *rk);
static int scan_for_next_relying_party(int index);
static int scan_for_next_resident_key(int index, uint8_t *initialRpIdHash);
static uint8_t verify_pin_auth_for_credential_management(CTAP_credMgmt *CM);

uint8_t ctap_credential_management(CborEncoder *encoder, uint8_t *request,
				   int length)
{
	CTAP_credMgmt CM;
	int i = 0;

	// RP / RK pointers
	static int curr_rp_ind = 0;
	static int curr_rk_ind = 0;

	// flags that authenticate whether *Begin was before *Next
	static bool rp_auth = false;
	static bool rk_auth = false;

	int rp_count = 0;
	int rk_count = 0;

	int ret = parse_credential_management_request(&CM, request, length);
	if (ret != 0) {
		printf2(TAG_ERR, "error, ctap_parse_cred_mgmt failed\n");
		return ret;
	}
	ret = verify_pin_auth_for_credential_management(&CM);
	check_retr(ret);
	if (STATE.rk_stored == 0 &&
	    CM.subCommand != CM_SubCmd_getCredsMetadata) {
		printf2(TAG_ERR, "No resident keys\n");
		return 0;
	}
	if (CM.subCommand == CM_SubCmd_enumerateRPsBegin) {
		curr_rk_ind = -1;
		rp_auth = true;
		rk_auth = false;
		curr_rp_ind = scan_for_next_relying_party(-1);

		// Count total unique RP's
		while (curr_rp_ind >= 0) {
			curr_rp_ind = scan_for_next_relying_party(curr_rp_ind);
			rp_count++;
		}

		// Reset scan
		curr_rp_ind = scan_for_next_relying_party(-1);

		printf1(TAG_MC, "RP Begin @%d.  %d total.\n", curr_rp_ind,
			rp_count);
	} else if (CM.subCommand == CM_SubCmd_enumerateCredentialsBegin) {
		int count = ctap_open_rk_file(CM.subCommandParams.rpIdHash);
		CTAP_residentKey rk;

		// TODO: Needs to be verified with updated load_rk api
		// An with new rp_id_lookup
		for (int i = 0; i < count; i++) {
			// ctap_load_rk(i, &rk);
			ctap_load_next_rk(&rk);
			if (memcmp(CM.subCommandParams.rpIdHash,
				   rk.rp.rp_id_hash, 32)) {
				// Not the right RPID
				continue;
			}
			rk_count++;
		}
		ctap_close_rk_file();
		// curr_rk_ind = scan_for_next_rk(0,
		// CM.subCommandParams.rpIdHash); rk_auth = true;
		//
		// // Count total RK's associated to RP
		// while (curr_rk_ind >= 0) {
		// 	curr_rk_ind = scan_for_next_rk(curr_rk_ind, NULL);
		// 	rk_count++;
		// }
		//
		// // Reset scan
		// curr_rk_ind = scan_for_next_rk(0,
		// CM.subCommandParams.rpIdHash);
		curr_rk_ind = 0; // Begin should always start with 0
		printf1(TAG_MC, "Cred Begin @%d.  %d total.\n", curr_rk_ind,
			rk_count);
	} else if (CM.subCommand !=
		       CM_SubCmd_enumerateCredentialsGetNextCredential &&
		   CM.subCommand != CM_SubCmd_enumerateRPsGetNextRP) {
		rk_auth = false;
		rp_auth = false;
		curr_rk_ind = -1;
		curr_rp_ind = -1;
	}

	switch (CM.subCommand) {
	case CM_SubCmd_getCredsMetadata:
		printf1(TAG_CM, "CM_SubCmd_getCredsMetadata\n");
		ret = cbor_encode_credential_metadata(encoder);
		check_ret(ret);
		break;
	case CM_SubCmd_enumerateRPsBegin:
	case CM_SubCmd_enumerateRPsGetNextRP:
		printf1(TAG_CM, "Get RP %d\n", curr_rp_ind);
		if (curr_rp_ind < 0 || !rp_auth) {
			rp_auth = false;
			rk_auth = false;
			return CTAP2_ERR_NO_CREDENTIALS;
		}

		ret = cbor_encode_relying_party(encoder, curr_rp_ind, rp_count);
		check_ret(ret);
		curr_rp_ind = scan_for_next_relying_party(curr_rp_ind);

		break;
	case CM_SubCmd_enumerateCredentialsBegin:
	case CM_SubCmd_enumerateCredentialsGetNextCredential:
		printf1(TAG_CM, "Get Cred %d\n", curr_rk_ind);
		if (curr_rk_ind < 0 || !rk_auth) {
			rp_auth = false;
			rk_auth = false;
			return CTAP2_ERR_NO_CREDENTIALS;
		}

		ret = cbor_encode_resident_key(encoder, curr_rk_ind, rk_count);
		check_ret(ret);

		curr_rk_ind = scan_for_next_resident_key(curr_rk_ind, NULL);

		break;
	case CM_SubCmd_deleteCredential:
		printf1(TAG_CM, "CM_SubCmd_deleteCredential\n");

		if (ctap_delete_rk(&CM.subCommandParams.credentialDescriptor
					.credential.id) < 0) {
			printf1(TAG_CM, "No Rk by given credId\n");
			return CTAP2_ERR_NO_CREDENTIALS;
		}
		ctap_decrement_rk_store();
		printf1(TAG_CM, "Deleted rk %d\n", i);

		// i = credentialId_to_rk_index(
		//     &CM.subCommandParams.credentialDescriptor.credential.id);
		// if (i >= 0) {
		// 	ctap_delete_rk(&CM.subCommandParams.credentialDescriptor
		// 			    .credential.id);
		// 	ctap_decrement_rk_store();
		// 	printf1(TAG_CM, "Deleted rk %d\n", i);
		// } else {
		// 	printf1(TAG_CM, "No Rk by given credId\n");
		// 	return CTAP2_ERR_NO_CREDENTIALS;
		// }
		break;
	default:
		printf2(TAG_ERR, "error, invalid credMgmt cmd: 0x%02x\n",
			CM.subCommand);
		return CTAP1_ERR_INVALID_COMMAND;
	}
	return 0;
}

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

static uint8_t cbor_encode_relying_party(CborEncoder *encoder, int rk_ind,
					 int rp_count)
{
	CTAP_residentKey rk;

	CborEncoder map;
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
		if (rk.rp.rp_id_size <= sizeof(rk.rp.rp_id)) {
			ret = cbor_encode_text_string(
			    &rp, (const char *)rk.rp.rp_id, rk.rp.rp_id_size);
		} else {
			ret = cbor_encode_text_string(&rp, "", 0);
		}
		check_ret(ret);
		ret = cbor_encode_text_stringz(&rp, "name");
		check_ret(ret);
		ret = cbor_encode_text_stringz(&rp, (const char *)rk.user.name);
		check_ret(ret);
		ret = cbor_encoder_close_container(&map, &rp);
		check_ret(ret);
	}
	ret = cbor_encode_int(&map, 4);
	check_ret(ret);
	cbor_encode_byte_string(&map, rk.rp.rp_id_hash, 32);
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

static uint8_t cbor_encode_resident_key(CborEncoder *encoder, int rk_ind,
					int rk_count)
{
	CTAP_residentKey rk;
	// TODO: This needs to be updated with the new load_rk api
	//  ctap_load_rk(rk_ind, &rk);

	uint8_t cred_protect = extract_cred_protect_from_metadata(&rk.id);
	if (cred_protect == 0 || cred_protect > 3) {
		// Take default value of userVerificationOptional
		cred_protect = EXT_CRED_PROTECT_OPTIONAL;
	}

	int32_t cose_alg = ctap_restore_metadata_cose_alg(&rk.id);

	CborEncoder map;
	size_t map_size = rk_count > 0 ? 5 : 4;
	int ret = cbor_encoder_create_map(encoder, &map, map_size);
	check_ret(ret);

	ret = cbor_encode_int(&map, 6);
	check_ret(ret);
	{
		ret = ctap_cbor_encode_user_entity(&map, &rk.user, 1);
		check_ret(ret);
	}

	ret = cbor_encode_int(&map, 7);
	check_ret(ret);
	{
		ret = ctap_cbor_encode_credential_descriptor(
		    &map, (struct Credential *)&rk, PUB_KEY_CRED_PUB_KEY);
		check_ret(ret);
	}

	ret = cbor_encode_int(&map, 8);
	check_ret(ret);
	{
		cose_key_generate(&map, (uint8_t *)&rk.id, sizeof(CredentialId),
				  PUB_KEY_CRED_PUB_KEY, cose_alg);
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

static uint8_t extract_cred_protect_from_metadata(CredentialId *credential)
{
	uint8_t metadata[CREDENTIAL_METADATA_SIZE];
	ctap_xcrypt_buf(credential->nonce, credential->protected_metadata,
			metadata, CREDENTIAL_METADATA_SIZE);

	return metadata[CREDENTIAL_META_CRED_PROTECT_BYTE];
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

	CborType type = cbor_value_get_type(&it);
	if (type != CborMapType) {
		printf2(TAG_ERR, "Error, expecting cbor map\n");
		return CTAP2_ERR_INVALID_CBOR;
	}

	ret = cbor_value_enter_container(&it, &map);
	check_ret(ret);

	ret = cbor_value_get_map_length(&it, &map_length);
	check_ret(ret);

	printf1(TAG_PARSE, "CM map has %d elements\n", map_length);

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

		switch (key) {
		case CM_Cmd_subCommand:
			printf1(TAG_PARSE, "CM_Cmd_subCommand\n");
			if (cbor_value_get_type(&map) == CborIntegerType) {
				ret = cbor_value_get_int_checked(
				    &map, &CM->subCommand);
				check_ret(ret);
				CM->hashed.subCommand = CM->subCommand;
			} else {
				return CTAP2_ERR_INVALID_CBOR;
			}
			break;
		case CM_Cmd_subCommandParams:
			printf1(TAG_PARSE, "CM_Cmd_subCommandParams\n");
			ret = parse_credential_management_subcommandparams(&map,
									   CM);
			check_ret(ret);
			break;
		case CM_Cmd_pinUvAuthProtocol:
			printf1(TAG_PARSE, "CM_Cmd_pinUvAuthProtocol\n");
			if (cbor_value_get_type(&map) == CborIntegerType) {
				ret = cbor_value_get_int_checked(
				    &map, &CM->pinProtocol);
				check_ret(ret);
			} else {
				return CTAP2_ERR_INVALID_CBOR;
			}
			break;
		case CM_Cmd_pinUvAuthParam:
			printf1(TAG_PARSE, "CM_Cmd_pinUvAuthParam\n");
			ret = ctap_parse_fixed_length_byte_string(
			    &map, CM->pinAuth, 16);
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
		printf2(TAG_ERR, "error, wrong type\n");
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
			;
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
	return (rk->id.count > 0 && rk->id.count != 0xffffffff);
}

// Load the next valid resident key of a different rpIdHash
static int scan_for_next_relying_party(int index)
{
	CTAP_residentKey rk;
	uint8_t nextRpIdHash[32];

	if (index == -1) {
		// TODO: Needs to be updated to new load_rk api
		//  ctap_load_rk(0, &rk);
		if (resident_key_is_valid(&rk)) {
			return 0;
		} else {
			index = 0;
		}
	}

	int occurs_previously;
	do {
		occurs_previously = 0;

		index++;
		if ((unsigned int)index >= ctap_max_number_of_rks()) {
			return -1;
		}

		// TODO: Needs to be updated to new load_rk api
		// ctap_load_rk(index, &rk);
		memmove(nextRpIdHash, rk.id.rp_id_lookup, 16);

		if (!resident_key_is_valid(&rk)) {
			occurs_previously = 1;
			continue;
		} else {
		}

		// Check if we have scanned the rpIdHash before.
		int i;
		for (i = 0; i < index; i++) {

			// TODO: Needs to be updated to new load_rk api
			// ctap_load_rk(i, &rk);
			if (memcmp(rk.id.rp_id_lookup, nextRpIdHash, 16) == 0) {
				occurs_previously = 1;
				break;
			}
		}

	} while (occurs_previously);

	return index;
}

// Load the next valid resident key of the same rpIdHash
static int scan_for_next_resident_key(int index, uint8_t *initialRpIdHash)
{
	CTAP_residentKey rk;
	uint8_t lastRpIdHash[32];

	if (initialRpIdHash != NULL) {
		memmove(lastRpIdHash, initialRpIdHash, 32);
		index = -1;
	} else {
		// TODO: Needs to be updated to new load_rk api
		// ctap_load_rk(index, &rk);
		memmove(lastRpIdHash, rk.id.rp_id_lookup, 16);
	}

	do {
		index++;
		if ((unsigned int)index >= ctap_max_number_of_rks()) {
			return -1;
		}
		// TODO: Needs to be updated to new load_rk api
		// ctap_load_rk(index, &rk);
	} while (memcmp(rk.id.rp_id_lookup, lastRpIdHash, 16) != 0);

	return index;
}

static uint8_t verify_pin_auth_for_credential_management(CTAP_credMgmt *CM)
{
	if (CM->subCommand != CM_SubCmd_getCredsMetadata &&
	    CM->subCommand != CM_SubCmd_enumerateRPsBegin &&
	    CM->subCommand != CM_SubCmd_enumerateCredentialsBegin &&
	    CM->subCommand != CM_SubCmd_deleteCredential) {
		// pinAuth is not required for other commands
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

// int credentialId_to_rk_index(CredentialId *credId)
//{
//	unsigned int i;
//	CTAP_residentKey rk;
//	// TODO: This function is most likely not needed anymore
//	for (i = 0; i < ctap_rk_size(); i++) {
//		// ctap_load_rk(i, &rk);
//		if (resident_key_is_valid(&rk)) {
//			if (memcmp(&rk.id, credId, sizeof(CredentialId)) == 0) {
//				return i;
//			}
//		}
//	}
//
//	return -1;
// }
