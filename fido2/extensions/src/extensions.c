// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include "extensions.h"
#include "device.h"
#include "u2f.h"
#include <stdint.h>

#include "log.h"

#define htonl(x)                                                               \
	(((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8) |    \
	 ((x & 0xff000000) >> 24))

static uint8_t *output_buffer_ptr;
uint8_t output_buffer_offset;
uint8_t output_buffer_size;

void extension_writeback_init(uint8_t *buffer, uint8_t size)
{
	output_buffer_ptr = buffer;
	output_buffer_offset = 0;
	output_buffer_size = size;
}

void extension_writeback(uint8_t *buf, uint8_t size)
{
	if ((output_buffer_offset + size) > output_buffer_size) {
		return;
	}
	memmove(output_buffer_ptr + output_buffer_offset, buf, size);
	output_buffer_offset += size;
}

uint16_t extend_u2f(APDU_HEADER *req, uint8_t *payload, uint32_t len)
{

	struct u2f_authenticate_request *auth =
	    (struct u2f_authenticate_request *)payload;
	uint16_t rcode;

	if (req->ins == U2F_AUTHENTICATE) {
		if (req->p1 == U2F_AUTHENTICATE_CHECK) {
			rcode = U2F_SW_WRONG_DATA;
			printf1(TAG_EXT, "Ignoring U2F check request\n");
			dump_hex1(TAG_EXT, (uint8_t *)&auth->kh, auth->khl);
			goto end;
		} else {
			rcode = U2F_SW_WRONG_DATA;
			printf1(TAG_EXT, "Ignoring U2F auth request\n");
			dump_hex1(TAG_EXT, (uint8_t *)&auth->kh, auth->khl);
			goto end;
		}
	} else if (req->ins == U2F_VERSION) {
		printf1(TAG_EXT, "U2F_VERSION\n");
		if (len) {
			rcode = U2F_SW_WRONG_LENGTH;
		} else {
			rcode = u2f_version();
		}
	} else {
		rcode = U2F_SW_INS_NOT_SUPPORTED;
	}
end:
	return rcode;
}
