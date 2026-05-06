// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_CLIENT_PIN_H_
#define _CTAP_CLIENT_PIN_H_

#include <stdint.h>
#include <stdlib.h>

#include "cbor.h"
#include "cose_key.h"

// clang-format off
/* CLIENT_PIN (0x06) */

// Commands
/* Map keys in the clientPin command */
#define CP_Cmd_pinUvAuthProtocol 0x01 // Data type: Unsigned Integer
#define CP_Cmd_subCommand        0x02 // Data type: Unsigned Integer
#define CP_Cmd_keyAgreement      0x03 // Data type: COSE_Key
#define CP_Cmd_pinUvAuthParam    0x04 // Data type: Byte String
#define CP_Cmd_newPinEnc         0x05 // Data type: Byte String
#define CP_Cmd_pinHashEnc        0x06 // Data type: Byte String
#define CP_Cmd_permissions       0x09 // Data type: Unsigned Integer
#define CP_Cmd_rpId              0x0A // Data type: String

// SubCommands
#define CP_SubCmd_getPINRetries                            0x01
#define CP_SubCmd_getKeyAgreement                          0x02
#define CP_SubCmd_setPIN                                   0x03
#define CP_SubCmd_changePIN                                0x04
#define CP_SubCmd_getPinToken                              0x05 // Superseded by getPinUvAuthTokenUsingUvWithPermissions or getPinUvAuthTokenUsingPinWithPermissions, thus for backwards compatibility only.
#define CP_SubCmd_getPinUvAuthTokenUsingUvWithPermissions  0x06
#define CP_SubCmd_getUVRetries                             0x07
#define CP_SubCmd_getPinUvAuthTokenUsingPinWithPermissions 0x09

// Response structures
#define CP_Resp_keyAgreement    0x01 // Data type: COSE_Key
#define CP_Resp_pinUvAuthToken  0x02 // Data type: Byte String
#define CP_Resp_pinRetries      0x03 // Data type: Unsigned Integer
#define CP_Resp_powerCycleState 0x04 // Data type: Boolean
#define CP_Resp_uvRetries       0x05 // Data type: Unsigned Integer

#define CP_pinUvAuthToken_permissions_mc    0x01 // MakeCredential,              RP ID: Required
#define CP_pinUvAuthToken_permissions_ga    0x02 // GetAssertion,                RP ID: Required
#define CP_pinUvAuthToken_permissions_cm    0x04 // Credential Management,       RP ID: Optional
#define CP_pinUvAuthToken_permissions_be    0x08 // Bio Enrollment,              RP ID: Ignored
#define CP_pinUvAuthToken_permissions_lbw   0x10 // Large Blob Write,            RP ID: Ignored
#define CP_pinUvAuthToken_permissions_acfg  0x20 // Authenticator Configuration, RP ID: Ignored

#define NEW_PIN_ENC_MAX_SIZE 256 // Includes NULL terminator
#define NEW_PIN_ENC_MIN_SIZE 64
#define NEW_PIN_MAX_SIZE     64
#define NEW_PIN_MIN_SIZE     4

#define PIN_LOCKOUT_ATTEMPTS 8 // Number of attempts total
#define PIN_BOOT_ATTEMPTS    3 // Number of attempts per boot

#define PIN_TOKEN_SIZE 16

// clang-format on

typedef struct {
	int pinProtocol;
	int subCommand;
	COSE_key keyAgreement;
	uint8_t keyAgreementPresent;
	uint8_t pinAuth[16];
	uint8_t pinAuthPresent;
	uint8_t newPinEnc[NEW_PIN_ENC_MAX_SIZE];
	int newPinEncSize;
	uint8_t pinHashEnc[16];
	uint8_t pinHashEncPresent;
	_Bool getKeyAgreement;
	_Bool getRetries;
} CTAP_clientPin;

uint8_t ctap_client_pin(CborEncoder *encoder, uint8_t *request, int length);
uint8_t ctap_client_pin_decrement_attempts();
int8_t ctap_client_pin_is_boot_locked();
int8_t ctap_client_pin_is_locked();
uint8_t ctap_client_pin_is_set();
void ctap_client_pin_reset_attempts();
void ctap_client_pin_reset_pin_token();
void ctap_client_pin_reset_key_agreement();
uint8_t ctap_client_pin_verify_auth(uint8_t *pinAuth, uint8_t *clientDataHash);
uint8_t ctap_client_pin_verify_auth_ex(uint8_t *pinAuth, uint8_t *buf,
				       size_t len);

#endif
