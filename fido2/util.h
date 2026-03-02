// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _UTIL_H
#define _UTIL_H

#include <stdbool.h>
#include <stdint.h>

int dump_hex(const uint8_t *buf, int size, int indent_pos,
	     bool indent_first_line, int start_pos, bool add_newline);

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#endif
