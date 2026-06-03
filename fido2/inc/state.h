// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _STATE_H
#define _STATE_H

#include "cbor.h"
#include "version.h"
#include <assert.h>
#include <stddef.h>
#include <stdint.h>

// clang-format off
#define STATE_VERSION               1
#define STATE_MAGIC                 0xA5
#define STATE_MAGIC_SIZE            1
#define STATE_MAC_SIZE              16
#define STATE_ENVELOPE_BUF_SIZE     192
#define STATE_PIN_HASH_SIZE         16
#define STATE_PIN_HASH_IV_SIZE      16
#define STATE_KEY_SALT_BYTES        64

// STATE_ENVELOPE_BUF_SIZE is expected size plus some margin

/* CBOR map keys for AuthenticatorState encoding / decoding */
/* 0–9: version / header */
#define STATE_CBOR_KEY_VERSION          0
#define STATE_CBOR_KEY_APP_VERSION      1

/* 10–19: PIN state */
#define STATE_CBOR_KEY_IS_PIN_SET       10
#define STATE_CBOR_KEY_REMAINING_TRIES  11
#define STATE_CBOR_KEY_PIN_HASH_ENC     12
#define STATE_CBOR_KEY_PIN_HASH_IV      13

/* 20–29: resident keys */
#define STATE_CBOR_KEY_RK_STORED        20

/* 30–39: key material */
#define STATE_CBOR_KEY_KEY_SALT         30
// clang-format on

// State documentation:
// The struct below is cbor encoded before stored on flash. To further assess
// the validity of the data it is enevloped with [magic(1)][mac(16)][cbor].
// Where the magic's purpose is a sanity check for initalized data. The mac
// provides authenticity of the cbor encoded data, and should be checked in that
// order. Valid magic, valid mac and den decode cbor.

typedef struct {
	uint8_t version;

	app_version_t app_version;

	uint8_t is_pin_set;
	int8_t remaining_tries;
	uint8_t pin_hash_enc[STATE_PIN_HASH_SIZE];
	uint8_t pin_hash_iv[STATE_PIN_HASH_IV_SIZE];

	uint16_t rk_stored;
	uint8_t key_salt[STATE_KEY_SALT_BYTES];
} AuthenticatorState;

// No accidental change to size of struct
static_assert(sizeof(AuthenticatorState) == 108,
	      "sizeof(AuthenticatorState) == 108");

CborError state_cbor_encode(uint8_t *buf, size_t buf_len,
			    const AuthenticatorState *s,
			    size_t *buf_encode_len);
CborError state_cbor_decode(AuthenticatorState *s, const uint8_t *buf,
			    size_t len);

extern AuthenticatorState STATE;

#endif
