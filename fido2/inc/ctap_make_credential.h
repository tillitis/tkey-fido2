// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_MAKE_CREDENTIAL_H_
#define _CTAP_MAKE_CREDENTIAL_H_

#include <stdint.h>

#include "cbor.h"
#include "ctap.h"
#include "ctap_client_pin.h"
#include "ctap_extensions.h"

// clang-format off
/* MAKE_CREDENTIAL (0x01) */

// Commands
#define MC_Cmd_clientDataHash        0x01 // Data type: Byte String
#define MC_Cmd_rp                    0x02 // Data type: PublicKeyCredentialRpEntity
#define MC_Cmd_user                  0x03 // Data type: PublicKeyCredentialUserEntity
#define MC_Cmd_pubKeyCredParams      0x04 // Data type: Array of PublicKeyCredentialParameters
#define MC_Cmd_excludeList           0x05 // Data type: Array of PublicKeyCredentialDescriptor
#define MC_Cmd_extensions            0x06 // Data type: CBOR map of extension identifier authenticator extension input values
#define MC_Cmd_options               0x07 // Data type: Map of authenticator options
#define MC_Cmd_pinUvAuthParam        0x08 // Data type: Byte String
#define MC_Cmd_pinUvAuthProtocol     0x09 // Data type: Unsigned Integer
#define MC_Cmd_enterpriseAttestation 0x0A // Data type: Unsigned Integer

// Response structures
#define MC_Resp_fmt                 0x01 // Data type: String
#define MC_Resp_authData            0x02 // Data type: Byte String
#define MC_Resp_attStmt             0x03 // Data type: CBOR Map, the structure of which depends on the attestation statement format identifier
#define MC_Resp_epAtt               0x04 // Data type: Boolean
#define MC_Resp_largeBlobKey        0x05 // Data type: Byte string
// clang-format on

typedef struct {
	uint32_t paramsParsed;
	uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
	struct rpId rp;

	CTAP_credInfo credInfo;

	CborValue excludeList;
	size_t excludeListSize;

	uint8_t uv;
	uint8_t up;

	uint8_t pinUvAuthParam[PIN_UV_AUTH_PARAM_MAX_SIZE];
	uint8_t pinUvAuthParam_present;
	// pinUvAuthParam_empty is true iff an empty bytestring was provided as
	// pinUvAuthParam. This is exclusive with |pinUvAuthParam_present|. It
	// exists because an empty pinUvAuthParam is a special signal to block
	// for touch. See
	// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#using-pinToken-in-authenticatorMakeCredential
	uint8_t pinUvAuthParam_empty;
	int pinProtocol;
	CTAP_extensions extensions;

} CTAP_makeCredential;

CtapStatus ctap_make_credential(CborEncoder *encoder, uint8_t *request,
				int length);

#endif
