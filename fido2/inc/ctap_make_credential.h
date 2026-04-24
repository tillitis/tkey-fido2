// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_MAKE_CREDENTIAL_H_
#define _CTAP_MAKE_CREDENTIAL_H_

#include <stdint.h>

#include "cbor.h"
#include "ctap.h"
#include "ctap_extensions.h"

typedef struct {
	uint32_t paramsParsed;
	uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
	struct rpId rp;

	CTAP_credInfo credInfo;

	CborValue excludeList;
	size_t excludeListSize;

	uint8_t uv;
	uint8_t up;

	uint8_t pinAuth[16];
	uint8_t pinAuthPresent;
	// pinAuthEmpty is true iff an empty bytestring was provided as pinAuth.
	// This is exclusive with |pinAuthPresent|. It exists because an empty
	// pinAuth is a special signal to block for touch. See
	// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#using-pinToken-in-authenticatorMakeCredential
	uint8_t pinAuthEmpty;
	int pinProtocol;
	CTAP_extensions extensions;

} CTAP_makeCredential;

uint8_t ctap_make_credential(CborEncoder *encoder, uint8_t *request,
			     int length);

#endif
