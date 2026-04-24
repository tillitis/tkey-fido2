// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_GET_ASSERTION_H_
#define _CTAP_GET_ASSERTION_H_

#include <stdint.h>

#include "cbor.h"
#include "ctap.h"
#include "ctap_extensions.h"

typedef struct {
	uint32_t paramsParsed;
	uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
	uint8_t clientDataHashPresent;

	struct rpId rp;

	int credLen;

	uint8_t rk;
	uint8_t uv;
	uint8_t up;

	uint8_t pinAuth[16];
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

uint8_t ctap_get_assertion(CborEncoder *encoder, uint8_t *request, int length);
uint8_t ctap_get_assertion_cbor_encode_assertion_response(
    CborEncoder *map, CTAP_credentialDescriptor *cred, uint8_t *auth_data_buf,
    unsigned int auth_data_buf_sz, uint8_t *clientDataHash);

#endif
