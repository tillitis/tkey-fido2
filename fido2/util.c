// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdint.h>
#include <stdio.h>

void dump_hex(uint8_t *buf, int size)
{
	while (size--) {
		printf("%02x ", *buf++);
	}
	printf("\n");
}
