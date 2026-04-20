// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_CREDENTIAL_MANAGEMENT_H_
#define _CTAP_CREDENTIAL_MANAGEMENT_H_

#include <stdint.h>

#include "cbor.h"
#include "ctap.h"

typedef struct {
	int cmd;
	struct {
		uint8_t rpIdHash[32];
		CTAP_credentialDescriptor credentialDescriptor;
	} subCommandParams;

	struct {
		uint8_t cmd;
		uint8_t
		    subCommandParamsCborCopy[sizeof(CTAP_credentialDescriptor) +
					     16];
	} hashed;
	uint32_t subCommandParamsCborSize;

	uint8_t pinAuth[16];
	uint8_t pinAuthPresent;
	int pinProtocol;
} CTAP_credMgmt;

uint8_t ctap_cred_metadata(CborEncoder *encoder);
uint8_t ctap_cred_mgmt(CborEncoder *encoder, uint8_t *request, int length);
uint8_t ctap_cred_mgmt_pinauth(CTAP_credMgmt *CM);
uint8_t ctap_cred_rk(CborEncoder *encoder, int rk_ind, int rk_count);
uint8_t ctap_cred_rp(CborEncoder *encoder, int rk_ind, int rp_count);
uint8_t ctap_parse_cred_mgmt(CTAP_credMgmt *CM, uint8_t *request, int length);
int ctap_rk_is_valid(CTAP_residentKey *rk);
uint8_t parse_cred_mgmt_subcommandparams(CborValue *val, CTAP_credMgmt *CM);
uint8_t restore_metadata_cred_protect(CredentialId *credential);
int scan_for_next_rk(int index, uint8_t *initialRpIdHash);
int scan_for_next_rp(int index);

#endif
