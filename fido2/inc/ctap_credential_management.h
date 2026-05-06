// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_CREDENTIAL_MANAGEMENT_H_
#define _CTAP_CREDENTIAL_MANAGEMENT_H_

#include <stdint.h>

#include "cbor.h"
#include "ctap.h"

// clang-format off
/* CREDENTIAL_MANAGEMENT (0x0A) */

// Commands
#define CM_Cmd_subCommand        0x01 // Data type: Unsigned Integer
#define CM_Cmd_subCommandParams  0x02 // Data type: CBOR Map
#define CM_Cmd_pinUvAuthProtocol 0x03 // Data type: Unsigned Integer
#define CM_Cmd_pinUvAuthParam    0x04 // Data type: Byte String

// SubCommands
#define CM_SubCmd_getCredsMetadata                      0x01
#define CM_SubCmd_enumerateRPsBegin                     0x02
#define CM_SubCmd_enumerateRPsGetNextRP                 0x03
#define CM_SubCmd_enumerateCredentialsBegin             0x04
#define CM_SubCmd_enumerateCredentialsGetNextCredential 0x05
#define CM_SubCmd_deleteCredential                      0x06
#define CM_SubCmd_updateUserInformation                 0x07

// SubCommandParams
#define CM_SubCmdParam_rpIDHash     0x01 // Data type: Byte String
#define CM_SubCmdParam_credentialID 0x02 // Data type: PublicKeyCredentialDescriptor
#define CM_SubCmdParam_user         0x03 // Data type: PublicKeyCredentialUserEntity

// Response structures
#define CM_Resp_existingResidentCredentialsCount             0x01 // Data type: Unsigned Integer
#define CM_Resp_maxPossibleRemainingResidentCredentialsCount 0x02 // Data type: Unsigned Integer
#define CM_Resp_rp                                           0x03 // Data type: PublicKeyCredentialRpEntity
#define CM_Resp_rpIDHash                                     0x04 // Data type: Byte String
#define CM_Resp_totalRPs                                     0x05 // Data type: Unsigned Integer
#define CM_Resp_user                                         0x06 // Data type: PublicKeyCredentialUserEntity
#define CM_Resp_credentialID                                 0x07 // Data type: PublicKeyCredentialDescriptor
#define CM_Resp_publicKey                                    0x08 // Data type: COSE_Key
#define CM_Resp_totalCredentials                             0x09 // Data type: Unsigned Integer
#define CM_Resp_credProtect                                  0x0A // Data type: Unsigned Integer
#define CM_Resp_largeBlobKey                                 0x0B // Data type: Byte string
// clang-format on

typedef struct {
	int subCommand;
	struct {
		uint8_t rpIdHash[32];
		CTAP_credentialDescriptor credentialDescriptor;
	} subCommandParams;

	struct {
		uint8_t subCommand;
		uint8_t
		    subCommandParamsCborCopy[sizeof(CTAP_credentialDescriptor) +
					     16];
	} hashed;
	uint32_t subCommandParamsCborSize;

	uint8_t pinAuth[16];
	uint8_t pinAuthPresent;
	int pinProtocol;
} CTAP_credMgmt;

uint8_t ctap_credential_management(CborEncoder *encoder, uint8_t *request,
				   int length);

#endif
