// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <cbor.h>
#include <cbor_util.h>
#include <stdint.h>

int encode_str_array(CborEncoder *map, uint8_t key, const char *const *items,
		     size_t count)
{
	int ret;
	CborEncoder arr;

	ret = cbor_encode_uint(map, key);
	if (ret)
		return ret;

	ret = cbor_encoder_create_array(map, &arr, count);
	if (ret)
		return ret;

	for (size_t i = 0; i < count; i++) {
		ret = cbor_encode_text_stringz(&arr, items[i]);
		if (ret)
			return ret;
	}

	return cbor_encoder_close_container(map, &arr);
}

int encode_stringz_bool(CborEncoder *map, const char *key, bool val)
{
	int ret = cbor_encode_text_stringz(map, key);
	if (ret)
		return ret;
	return cbor_encode_boolean(map, val);
}

int encode_stringz_int(CborEncoder *map, const char *key, int val)
{
	int ret = cbor_encode_text_stringz(map, key);
	if (ret)
		return ret;
	return cbor_encode_int(map, val);
}

int encode_stringz_stringz(CborEncoder *map, const char *key, const char *val)
{
	int ret = cbor_encode_text_stringz(map, key);
	if (ret)
		return ret;
	return cbor_encode_text_stringz(map, val);
}

int encode_uint_kv(CborEncoder *map, uint8_t key, uint32_t val)
{
	int ret = cbor_encode_uint(map, key);
	if (ret)
		return ret;
	return cbor_encode_uint(map, val);
}
