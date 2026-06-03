// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cbor.h"
#include "ctap_parse.h"
#include "log.h"
#include "state.h"

static bool get_u8(CborValue *it, uint8_t *out)
{
	uint64_t tmp;
	if (cbor_value_get_uint64(it, &tmp) != CborNoError)
		return -2;

	if (tmp > UINT8_MAX)
		return -1;

	*out = (uint8_t)tmp;
	return 0;
}

static bool get_u16(CborValue *it, uint16_t *out)
{
	uint64_t tmp;
	if (cbor_value_get_uint64(it, &tmp) != CborNoError)
		return -2;

	if (tmp > UINT16_MAX)
		return -1;

	*out = (uint16_t)tmp;
	return 0;
}

static bool get_u32(CborValue *it, uint32_t *out)
{
	uint64_t tmp;
	if (cbor_value_get_uint64(it, &tmp) != CborNoError)
		return -2;

	if (tmp > UINT32_MAX)
		return -1;

	*out = (uint32_t)tmp;
	return 0;
}

static bool get_i8(CborValue *it, int8_t *out)
{
	int64_t tmp;

	if (cbor_value_get_int64(it, &tmp) != CborNoError)
		return -2;

	if (tmp < INT8_MIN || tmp > INT8_MAX)
		return -1;

	*out = (int8_t)tmp;
	return 0;
}
/*
 * Encode AuthenticatorState into a CBOR-encoded buffer.
 *
 * Writes the fields of @p s into @p buf as a definite-length CBOR map
 * using numeric keys. On success, the encoded length is written to
 * @p buf_encode_len.
 *
 * @param[out] buf            Output buffer to write the CBOR data to.
 * @param[in]  buf_len        Length of the output buffer.
 * @param[in]  s              Pointer to AuthenticatorState to encode.
 * @param[out] buf_encode_len Pointer to store the final encoded length.
 * @return                    CborError error code.
 * failure.
 */
CborError state_cbor_encode(uint8_t *buf, size_t buf_len,
			    const AuthenticatorState *s, size_t *buf_encode_len)
{
	CborEncoder encoder, map;
	CborError err;

	cbor_encoder_init(&encoder, buf, buf_len, 0);
	err = cbor_encoder_create_map(&encoder, &map, 8);
	cbor_check_retr(err);

	// 0: version
	err = cbor_encode_uint(&map, STATE_CBOR_KEY_VERSION);
	cbor_check_retr(err);
	err = cbor_encode_uint(&map, s->version);
	cbor_check_retr(err);

	// 2: app_version
	err = cbor_encode_uint(&map, STATE_CBOR_KEY_APP_VERSION);
	cbor_check_retr(err);
	err = cbor_encode_uint(&map, s->app_version.raw);
	cbor_check_retr(err);

	// 3: is_pin_set
	err = cbor_encode_uint(&map, STATE_CBOR_KEY_IS_PIN_SET);
	cbor_check_retr(err);
	err = cbor_encode_uint(&map, s->is_pin_set);
	cbor_check_retr(err);

	// 4: remaining_tries
	err = cbor_encode_uint(&map, STATE_CBOR_KEY_REMAINING_TRIES);
	cbor_check_retr(err);
	err = cbor_encode_int(&map, s->remaining_tries);
	cbor_check_retr(err);

	// 5: PIN_CODE_HASH
	err = cbor_encode_uint(&map, STATE_CBOR_KEY_PIN_HASH_ENC);
	cbor_check_retr(err);
	err =
	    cbor_encode_byte_string(&map, s->pin_hash_enc, STATE_PIN_HASH_SIZE);
	cbor_check_retr(err);

	// 6: PIN_SALT
	err = cbor_encode_uint(&map, STATE_CBOR_KEY_PIN_HASH_IV);
	cbor_check_retr(err);
	err = cbor_encode_byte_string(&map, s->pin_hash_iv,
				      STATE_PIN_HASH_IV_SIZE);
	cbor_check_retr(err);

	// 7: rk_stored
	err = cbor_encode_uint(&map, STATE_CBOR_KEY_RK_STORED);
	cbor_check_retr(err);
	err = cbor_encode_uint(&map, s->rk_stored);
	cbor_check_retr(err);

	// 8: key_salt
	err = cbor_encode_uint(&map, STATE_CBOR_KEY_KEY_SALT);
	cbor_check_retr(err);
	err = cbor_encode_byte_string(&map, s->key_salt, STATE_KEY_SALT_BYTES);
	cbor_check_retr(err);

	err = cbor_encoder_close_container(&encoder, &map);
	cbor_check_retr(err);

	*buf_encode_len = cbor_encoder_get_buffer_size(&encoder, buf);

	return CborNoError;
}

/**
 * Decode AuthenticatorState from a CBOR-encoded buffer.
 *
 * Parses a canonical CBOR map and populates the AuthenticatorState fields.
 * Returns false if parsing fails or the state version is unsupported.
 *
 * @param[out] s   Pointer to AuthenticatorState to populate.
 * @param[in]  buf CBOR-encoded input buffer.
 * @param[in]  len Length of the input buffer.
 * @return         zero on success, -1 for logic error and -2 for cbor decode
 * error.
 */
int state_cbor_decode(AuthenticatorState *s, const uint8_t *buf, size_t len)
{
	CborValue it, map;
	CborParser parser;
	int ret;

	if (cbor_parser_init(buf, len, CborValidateCanonicalFormat, &parser,
			     &it) != CborNoError) {
		printf1(TAG_CTAP, "start_des: init fail\n");
		return -2;
	}

	if (cbor_value_enter_container(&it, &map) != CborNoError) {
		printf1(TAG_CTAP, "start_des: enter container fail\n");
		return -2;
	}

	while (!cbor_value_at_end(&map)) {

		uint64_t key;
		size_t sz;
		if (cbor_value_get_uint64(&map, &key) != CborNoError) {
			printf1(TAG_CTAP, "start_des: get key fail\n");
			return -2;
		}

		cbor_value_advance(&map);

		switch (key) {

		case STATE_CBOR_KEY_VERSION:
			ret = get_u8(&map, &s->version);
			if (ret != 0) {
				printf1(TAG_CTAP,
					"start_des: get version fail\n");
				return ret;
			}
			// The only known version
			if (s->version != STATE_VERSION) {
				printf1(TAG_CTAP,
					"start_des: wrong version fail\n");
				return -1;
			}
			break;
		case STATE_CBOR_KEY_APP_VERSION:
			ret = get_u32(&map, &s->app_version.raw);
			if (ret != 0) {
				printf1(TAG_CTAP,
					"start_des: app_version fail\n");
				return ret;
			}
			break;

		case STATE_CBOR_KEY_IS_PIN_SET:
			ret = get_u8(&map, &s->is_pin_set);
			if (ret != 0) {
				printf1(TAG_CTAP, "start_des: pin set fail\n");
				return ret;
			}
			break;

		case STATE_CBOR_KEY_REMAINING_TRIES:
			ret = get_i8(&map, &s->remaining_tries);
			if (ret != 0) {
				printf1(TAG_CTAP, "start_des: remain fail\n");
				return ret;
			}
			break;

		case STATE_CBOR_KEY_PIN_HASH_ENC:
			sz = STATE_PIN_HASH_SIZE;
			if (cbor_value_copy_byte_string(&map, s->pin_hash_enc,
							&sz,
							NULL) != CborNoError) {
				return -2;
			}
			break;

		case STATE_CBOR_KEY_PIN_HASH_IV:
			sz = STATE_PIN_HASH_IV_SIZE;
			if (cbor_value_copy_byte_string(&map, s->pin_hash_iv,
							&sz,
							NULL) != CborNoError) {
				return -2;
			}
			break;

		case STATE_CBOR_KEY_RK_STORED:
			ret = get_u16(&map, &s->rk_stored);
			if (ret != 0) {
				return ret;
			}
			break;

		case STATE_CBOR_KEY_KEY_SALT:
			sz = STATE_KEY_SALT_BYTES;
			if (cbor_value_copy_byte_string(&map, s->key_salt, &sz,
							NULL) != CborNoError) {
				return -2;
			}

			break;

		default:
			// forward compatibility
			cbor_value_advance(&map);
			break;
		}

		cbor_value_advance(&map);
	}

	return 0;
}
