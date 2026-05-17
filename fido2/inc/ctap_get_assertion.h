// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_GET_ASSERTION_H_
#define _CTAP_GET_ASSERTION_H_

#include <stdint.h>

#include "cbor.h"
#include "ctap.h"
#include "ctap_client_pin.h"
#include "ctap_extensions.h"

// clang-format off
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
// clang-format on

typedef struct {
	uint32_t paramsParsed;
	uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
	uint8_t clientDataHashPresent;

	struct rpId rp;

	int credLen;

	uint8_t rk;
	uint8_t uv;
	uint8_t up;

	uint8_t pinAuth[PIN_UV_AUTH_PARAM_MAX_SIZE];
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

CtapStatus ctap_get_assertion(CborEncoder *encoder, uint8_t *request,
			      int length);
CtapStatus ctap_get_assertion_cbor_encode_assertion_response(
    CborEncoder *map, CTAP_credentialDescriptor *cred, uint8_t *auth_data_buf,
    unsigned int auth_data_buf_sz, uint8_t *clientDataHash);

#endif
