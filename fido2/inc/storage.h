// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _STORAGE_H
#define _STORAGE_H

#include <stdint.h>

#define KEY_SALT_BYTES 64
#define PIN_SALT_LEN (32)
#define STATE_VERSION (1)

#define BACKUP_MARKER 0x5A
#define INITIALIZED_MARKER 0xA5

typedef struct {
	// Pin information
	uint8_t is_initialized;
	uint8_t is_pin_set;
	uint8_t PIN_CODE_HASH[32];
	uint8_t PIN_SALT[PIN_SALT_LEN];
	int _reserved;
	int8_t remaining_tries;

	uint16_t rk_stored;

	uint8_t key_salt[KEY_SALT_BYTES];
	uint8_t data_version;
} AuthenticatorState_0x01;

typedef AuthenticatorState_0x01 AuthenticatorState;

typedef struct {
	uint32_t addr;
	uint8_t *filename;
	uint32_t count;
} AuthenticatorCounter;

extern AuthenticatorState STATE;

#endif
