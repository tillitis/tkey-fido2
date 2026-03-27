
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CBOR_UTIL_H
#define _CBOR_UTIL_H

#include "cbor.h"
#include <stdint.h>

int encode_str_array(CborEncoder *map, uint8_t key, const char *const *items,
		     size_t count);
int encode_uint_kv(CborEncoder *map, uint8_t key, uint32_t val);
int encode_stringz_bool(CborEncoder *map, const char *key, bool val);
int encode_stringz_int(CborEncoder *map, const char *key, int val);
int encode_stringz_stringz(CborEncoder *map, const char *key, const char *val);

#endif
