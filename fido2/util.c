// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

int dump_hex(const uint8_t *buf, int size, int indent_pos,
	     bool indent_first_line, int start_pos, bool add_newline)
{
	int pos = (start_pos > 0) ? start_pos : 1;

	if (size > 0) {
		if (indent_first_line) {
			for (int j = 0; j < indent_pos; j++) {
				printf(" ");
			}
		}
	}

	for (int i = 0; i < size; i++) {
		printf("%02X ", *buf++);
		if ((pos % 16) == 0) {
			printf("\n");
			if ((i + 1) < size) {
				for (int j = 0; j < indent_pos; j++) {
					printf(" ");
				}
			}
		}
		pos++;
	}
	if (add_newline) {
		if (((pos - 1) % 16) != 0) {
			printf("\n");
		}
	}

	return pos;
}
