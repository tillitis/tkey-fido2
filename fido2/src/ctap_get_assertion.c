#include <stdint.h>
#include <stdlib.h>

#include "crypto.h"
#include "ctap_client_pin.h"
#include "ctap_errors.h"
#include "ctap_get_assertion.h"
#include "ctap_make_credential.h"
#include "ctap_parse.h"
#include "device.h"
#include "log.h"

extern struct _getAssertionState getAssertionState;

static int build_filtered_credential_list(CTAP_getAssertion *GA,
					  uint8_t *rp_id_hash,
					  uint8_t *rp_id_lookup);
static int cred_cmp_func(const void *_a, const void *_b);
static uint8_t parse_allow_list_credentials(CTAP_getAssertion *GA,
					    CborValue *it);
static uint8_t parse_get_assertion_request(CTAP_getAssertion *GA,
					   uint8_t *request, int length);
static int8_t save_credential_list(uint8_t *clientDataHash,
				   CTAP_credentialDescriptor *creds,
				   uint32_t count, CTAP_extensions *extensions);

uint8_t ctap_get_assertion(CborEncoder *encoder, uint8_t *request, int length)
{
	CTAP_getAssertion GA;

	int ret = parse_get_assertion_request(&GA, request, length);

	if (ret != 0) {
		printf2(TAG_ERR,
			"Error, parse_get_assertion_request() failed\n");
		return ret;
	}

	if (GA.pinAuthEmpty) {
		ret = ctap2_user_presence_test();
		check_retr(ret);
		return ctap_client_pin_is_set() == 1
			   ? CTAP2_ERR_PIN_AUTH_INVALID
			   : CTAP2_ERR_PIN_NOT_SET;
	}
	if (GA.pinAuthPresent) {
		ret =
		    ctap_client_pin_verify_auth(GA.pinAuth, GA.clientDataHash);
		check_retr(ret);
		getAssertionState.user_verified = 1;
	} else {
		getAssertionState.user_verified = 0;
	}

	if (!GA.rp.size || !GA.clientDataHashPresent) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}
	CborEncoder map;

	int map_size = 3;

	uint8_t rp_id_hash[32];
	uint8_t rp_id_lookup[CREDENTIAL_TAG_SIZE];
	ctap_derive_rp_id_info(GA.rp.id, GA.rp.size, rp_id_hash, rp_id_lookup);

	printf1(TAG_GA, "rpid:\n");
	dump_hex1(TAG_GA, rp_id_hash, sizeof(rp_id_hash));
	printf1(TAG_GA, "rpid_lookup:\n");
	dump_hex1(TAG_GA, rp_id_lookup, sizeof(rp_id_lookup));

	printf1(TAG_GA, "ALLOW_LIST has %d creds\n", GA.credLen);
	int validCredCount =
	    build_filtered_credential_list(&GA, rp_id_hash, rp_id_lookup);

	if (validCredCount == 0) {
		printf2(TAG_ERR, "Error, no authentic credential\n");
		return CTAP2_ERR_NO_CREDENTIALS;
	} else if (validCredCount > 1) {
		map_size += 1;
	}

	printf1(TAG_GREEN, "2 USER ID SIZE: %d\n",
		GA.creds[0].credential.user.id_size);

	if (GA.creds[validCredCount - 1].credential.user.id_size) {
		map_size += 1;
	}
	if (GA.extensions.hmac_secret_present == EXT_HMAC_SECRET_PARSED) {
		printf1(TAG_GA, "hmac-secret is present\n");
	}

	ret = cbor_encoder_create_map(encoder, &map, map_size);
	check_ret(ret);

	// if only one account for this RP, null out the user details
	if (validCredCount < 2 || !getAssertionState.user_verified) {
		printf1(TAG_GREEN, "Only one account, nulling out user details "
				   "on response\n");
		memset(&GA.creds[0].credential.user.name, 0, USER_NAME_LIMIT);
	}

	printf1(TAG_GA, "resulting order of creds:\n");
	int j;
	for (j = 0; j < GA.credLen; j++) {
		printf1(TAG_GA, "CRED ID (# %d)\n",
			GA.creds[j].credential.id.count);
	}

	CTAP_credentialDescriptor *cred = &GA.creds[0];

	GA.extensions.hmac_secret.credential = &cred->credential;

	uint32_t auth_data_buf_sz = sizeof(CTAP_authDataHeader);

#ifdef ENABLE_U2F_EXTENSIONS
	if (is_extension_request((uint8_t *)&GA.creds[0].credential.id,
				 sizeof(CredentialId))) {
		crypto_sha256_init();
		crypto_sha256_update(GA.rp.id, GA.rp.size);
		crypto_sha256_final(getAssertionState.buf.authData.rpIdHash);

		getAssertionState.buf.authData.flags = (1 << 0);
		getAssertionState.buf.authData.flags |= (1 << 2);
	} else
#endif
	{
		device_disable_up(GA.up == 0);
		ret = ctap_make_auth_data(
		    &GA.rp, rp_id_hash, rp_id_lookup, &map,
		    (uint8_t *)&getAssertionState.buf.authData,
		    &auth_data_buf_sz, NULL, &GA.extensions);
		device_disable_up(false);
		check_retr(ret);

		getAssertionState.buf.authData.flags &= ~(1 << 2);
		getAssertionState.buf.authData.flags |=
		    (getAssertionState.user_verified << 2);

		{
			unsigned int ext_encoder_buf_size =
			    sizeof(getAssertionState.buf.extensions);

			ret = ctap_extensions_encode_output(
			    &GA.extensions, getAssertionState.buf.extensions,
			    &ext_encoder_buf_size);
			check_retr(ret);
			if (ext_encoder_buf_size) {
				getAssertionState.buf.authData.flags |=
				    (1 << 7);
				auth_data_buf_sz += ext_encoder_buf_size;
			}
		}
	}

	ret = ctap_get_assertion_cbor_encode_assertion_response(
	    &map, cred, (uint8_t *)&getAssertionState.buf, auth_data_buf_sz,
	    GA.clientDataHash); // 1,2,3,4
	check_retr(ret);

	if (validCredCount > 1) {
		ret = cbor_encode_int(&map, GA_Resp_numberOfCredentials);
		check_ret(ret);
		ret = cbor_encode_int(&map, validCredCount);
		check_ret(ret);
	}

	ret = cbor_encoder_close_container(encoder, &map);
	check_ret(ret);

	ret = save_credential_list(GA.clientDataHash,
				   GA.creds + 1 /* skip first credential*/,
				   validCredCount - 1, &GA.extensions);
	check_retr(ret);

	return 0;
}

// adds 2 to map, or 3 if add_user is true
uint8_t ctap_get_assertion_cbor_encode_assertion_response(
    CborEncoder *map, CTAP_credentialDescriptor *cred, uint8_t *auth_data_buf,
    unsigned int auth_data_buf_sz, uint8_t *clientDataHash)
{
	int ret;
	uint8_t sigbuf[64];
	uint8_t sigder[72];
	int sigder_sz;

	ret = cbor_encode_int(map, GA_Resp_credential);
	check_ret(ret);

	ret = ctap_cbor_encode_credential_descriptor(map, &cred->credential,
						     cred->type);
	check_retr(ret);

	{
		ret = cbor_encode_int(map, MC_Resp_authData);
		check_ret(ret);
		ret = cbor_encode_byte_string(map, auth_data_buf,
					      auth_data_buf_sz);
		check_ret(ret);
	}

	size_t cred_size = ctap_get_credential_id_size(cred->type);
	int32_t cose_alg = ctap_restore_metadata_cose_alg(&cred->credential.id);
	if (cose_alg == COSE_ALG_EDDSA) {
		fido2_crypto_ed25519_load_key((uint8_t *)&cred->credential.id,
					      cred_size);
	} else {
		crypto_ecc256_load_key((uint8_t *)&cred->credential.id,
				       cred_size, NULL, 0);
	}

#ifdef ENABLE_U2F_EXTENSIONS
	if (extend_fido2(&cred->credential.id, sigder)) {
		sigder_sz = 72;
	} else
#endif
	{
		sigder_sz = ctap_sign_data(auth_data_buf, auth_data_buf_sz,
					   clientDataHash, auth_data_buf,
					   sigbuf, sigder, cose_alg);
	}

	printf1(TAG_GREEN, "sigder_sz = %d\n", sigder_sz);

	{
		ret = cbor_encode_int(map, GA_Resp_signature);
		check_ret(ret);
		ret = cbor_encode_byte_string(map, sigder, sigder_sz);
		check_ret(ret);
	}

	if (cred->credential.user.id_size) {
		printf1(TAG_GREEN, "adding user details to output\n");

		int ret = cbor_encode_int(map, GA_Resp_user);
		check_ret(ret);

		ret = ctap_cbor_encode_user_entity(
		    map, &cred->credential.user,
		    getAssertionState.user_verified);
		check_retr(ret);
	}

	return 0;
}

// @return the number of valid credentials
// sorts the credentials.  Most recent creds will be first, invalid ones
// last.
static int build_filtered_credential_list(CTAP_getAssertion *GA,
					  uint8_t *rp_id_hash,
					  uint8_t *rp_id_lookup)
{
	unsigned int i;
	int count = 0;
	CTAP_residentKey rk;

	for (i = 0; i < (unsigned int)GA->credLen; i++) {

		CTAP_credentialDescriptor *cred = &GA->creds[i];
		uint8_t is_rk = 0;

		if (!ctap_credential_belongs_to_rp(rp_id_lookup, rp_id_hash,
						   cred)) {
#ifdef ENABLE_U2F_EXTENSIONS
			if (is_extension_request(
				(uint8_t *)&cred->credential.id,
				sizeof(CredentialId))) {
				printf1(TAG_EXT, "CRED #%d is extension\n",
					cred->credential.id.count);
				count++;
			} else
#endif
			{

				printf1(TAG_GA,
					"allowList: CRED #%d is invalid\n",
					cred->credential.id.count);

				cred->credential.id.count = 0; // invalidate
			}
			continue;
		}

		int protection_status = ctap_check_credential_metadata(
		    &cred->credential.id, getAssertionState.user_verified, 1,
		    &is_rk);

		if (protection_status != 0) {
			printf1(TAG_GREEN,
				"allowList: skipping protected credential.\n");
			cred->credential.id.count = 0; // invalidate
			continue;
		}

		// If it is discoverable, verify that it still exists -
		// otherwise invalidate
		if (is_rk) {
			if (!ctap_verify_rk_exists(&cred->credential.id)) {
				cred->credential.id.count = 0; // invalidate
				continue;
			}
		}

		count++;
		GA->credLen = i + 1;
	}

	// No allowList, so use all matching RK's matching rpId
	if (!GA->credLen) {

		int nr_rk = ctap_open_rk_file(rp_id_lookup);
		if (nr_rk < 0) {
			printf1(TAG_GREEN, "No file to open: %d\n", nr_rk);
			nr_rk = 0;
		}

		for (i = 0; i < nr_rk; i++) {

			ctap_load_next_rk(&rk);

			printf1(TAG_GREEN, "rp_id_lookup %d:\n", i);
			dump_hex1(TAG_GREEN, rk.id.rp_id_lookup,
				  CREDENTIAL_TAG_SIZE);

			if (memcmp(rp_id_lookup, rk.id.rp_id_lookup,
				   CREDENTIAL_TAG_SIZE)) {
				// Not the right RPID
				continue;
			}

			// Verify credential mac
			uint8_t local_tag[16];
			ctap_make_auth_tag(rp_id_lookup, rk.id.nonce,
					   rk.id.protected_metadata,
					   rk.id.count, local_tag);

			if (memcmp(rk.id.tag, local_tag, CREDENTIAL_TAG_SIZE) !=
			    0) {
				printf1(TAG_GREEN,
					"Cred failed mac verification\n");
				continue;
			}

			// Check cred protect
			uint8_t is_rk = 0;
			int protection_status = ctap_check_credential_metadata(
			    &rk.id, getAssertionState.user_verified, 0, &is_rk);

			if (protection_status != 0) {
				printf1(TAG_GREEN,
					"Skipping protected rk credential.\n");
				continue;
			}

			if (count >= ALLOW_LIST_MAX_SIZE) {
				printf2(TAG_ERR,
					"not enough ram allocated for "
					"matching RK's (%d).  "
					"Skipping.\n",
					count);
				break;
			}

			// Verify mac over the residential key.
			if (!ctap_verify_mac(rk.rk_tag, &rk.user,
					     RK_HMAC_SIZE)) {
				printf1(TAG_GREEN,
					"rk failed mac verification\n");
				continue;
			}

			// Decrypt user data in place
			ctap_xcrypt_buf(rk.rk_nonce, &rk.user, &rk.user,
					sizeof(CTAP_userEntity) +
					    sizeof(rpEntity));

			GA->creds[count].type = PUB_KEY_CRED_PUB_KEY;

			memmove(&GA->creds[count].credential.id, &rk.id,
				sizeof(CredentialId));

			// Fill in user as well, needed by RP
			memmove(&GA->creds[count].credential.user, &rk.user,
				sizeof(CTAP_userEntity));

			count++;
		}
		ctap_close_rk_file();
		GA->credLen = count;
	}

	printf1(TAG_GA, "qsort length: %d\n", GA->credLen);
	qsort(GA->creds, GA->credLen, sizeof(CTAP_credentialDescriptor),
	      cred_cmp_func);
	return count;
}

static int cred_cmp_func(const void *_a, const void *_b)
{
	CTAP_credentialDescriptor *a = (CTAP_credentialDescriptor *)_a;
	CTAP_credentialDescriptor *b = (CTAP_credentialDescriptor *)_b;
	return b->credential.id.count - a->credential.id.count;
}

static uint8_t parse_get_assertion_request(CTAP_getAssertion *GA,
					   uint8_t *request, int length)
{
	int ret;
	unsigned int i;
	int key;
	size_t map_length;
	CborParser parser;
	CborValue it, map;

	memset(GA, 0, sizeof(CTAP_getAssertion));
	GA->creds = getAssertionState.creds; // Save stack memory
	GA->up = 0xff;

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

	printf1(TAG_GA, "GA map has %d elements\n", map_length);

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

		case GA_Cmd_clientDataHash:
			printf1(TAG_GA, "GA_Cmd_clientDataHash\n");

			ret = ctap_parse_fixed_length_byte_string(
			    &map, GA->clientDataHash, CLIENT_DATA_HASH_SIZE);
			check_retr(ret);
			GA->clientDataHashPresent = 1;

			printf1(TAG_GA, "\n");
			dump_hex1(TAG_GA, GA->clientDataHash, 32);
			break;

		case GA_Cmd_rpId:
			printf1(TAG_GA, "GA_Cmd_rpId\n");

			ret = ctap_parse_rp_id(&GA->rp, &map);

			printf1(TAG_GA, "  ID: %s\n", GA->rp.id);
			break;

		case GA_Cmd_allowList:
			printf1(TAG_GA, "GA_Cmd_allowList\n");
			ret = parse_allow_list_credentials(GA, &map);
			check_ret(ret);
			GA->allowListPresent = 1;
			break;

		case GA_Cmd_extensions:
			printf1(TAG_GA, "GA_Cmd_extensions\n");
			ret =
			    ctap_extensions_parse_input(&map, &GA->extensions);
			check_retr(ret);
			break;

		case GA_Cmd_options:
			printf1(TAG_GA, "GA_Cmd_options\n");
			ret =
			    ctap_parse_options(&map, &GA->rk, &GA->uv, &GA->up);
			check_retr(ret);
			break;

		case GA_Cmd_pinUvAuthParam:
			printf1(TAG_GA, "GA_Cmd_pinUvAuthParam\n");

			size_t pinSize;
			if (cbor_value_get_type(&map) != CborByteStringType) {
				printf2(TAG_ERR, "Error, expecting byte string "
						 "for map key\n");
				return CTAP2_ERR_INVALID_CBOR;
			}
			if (cbor_value_get_string_length(&map, &pinSize) !=
			    CborNoError) {
				printf2(TAG_ERR, "Error, invalid map data\n");
				return CTAP2_ERR_INVALID_CBOR;
			}
			if (pinSize == 0) {
				GA->pinAuthEmpty = 1;
				break;
			}

			ret = ctap_parse_fixed_length_byte_string(
			    &map, GA->pinAuth, PIN_UV_AUTH_PARAM_MAX_SIZE);
			if (CTAP1_ERR_INVALID_LENGTH != ret) // damn microsoft
			{
				check_retr(ret);

			} else {
				ret = 0;
			}

			check_retr(ret);
			GA->pinAuthPresent = 1;

			break;

		case GA_Cmd_pinUvAuthProtocol:
			printf1(TAG_GA, "GA_Cmd_pinUvAuthProtocol\n");
			if (cbor_value_get_type(&map) == CborIntegerType) {
				ret = cbor_value_get_int_checked(
				    &map, &GA->pinProtocol);
				check_ret(ret);
			} else {
				return CTAP2_ERR_INVALID_CBOR;
			}

			break;
		}

		if (ret != 0) {
			printf2(TAG_ERR, "Error, parsing failed\n");
			return ret;
		}

		ret = cbor_value_advance(&map);
		check_ret(ret);
	}

	return 0;
}

static uint8_t parse_allow_list_credentials(CTAP_getAssertion *GA,
					    CborValue *it)
{
	CborValue arr;
	size_t len;
	int ret;
	unsigned int i;
	CTAP_credentialDescriptor *cred;

	if (cbor_value_get_type(it) != CborArrayType) {
		printf2(TAG_ERR, "Error, expecting cbor array\n");
		return CTAP2_ERR_INVALID_CBOR;
	}

	ret = cbor_value_enter_container(it, &arr);
	check_ret(ret);

	ret = cbor_value_get_array_length(it, &len);
	check_ret(ret);

	GA->credLen = 0;

	for (i = 0; i < len; i++) {
		if (i >= ALLOW_LIST_MAX_SIZE) {
			printf1(TAG_PARSE,
				"Error, out of memory for allow list.\n");
			return CTAP2_ERR_LIMIT_EXCEEDED;
		}

		GA->credLen += 1;
		cred = &GA->creds[i];

		memset(cred, 0, sizeof(CTAP_credentialDescriptor));
		ret = ctap_parse_pubkey_credential_descriptor(&arr, cred);
		check_retr(ret);

		ret = cbor_value_advance(&arr);
		check_ret(ret);
	}
	return 0;
}

static int8_t save_credential_list(uint8_t *clientDataHash,
				   CTAP_credentialDescriptor *creds,
				   uint32_t count, CTAP_extensions *extensions)
{
	if (count) {
		if (count > ALLOW_LIST_MAX_SIZE - 1) {
			printf2(TAG_ERR, "ALLOW_LIST_MAX_SIZE Exceeded\n");
			return CTAP2_ERR_LIMIT_EXCEEDED;
		}

		memmove(getAssertionState.clientDataHash, clientDataHash,
			CLIENT_DATA_HASH_SIZE);
		memmove(getAssertionState.creds, creds,
			sizeof(CTAP_credentialDescriptor) * (count));
		memmove(&getAssertionState.extensions, extensions,
			sizeof(CTAP_extensions));
	}
	getAssertionState.count = count;
	getAssertionState.index = 0;
	printf1(TAG_GA, "saved %d credentials\n", count);
	return 0;
}
