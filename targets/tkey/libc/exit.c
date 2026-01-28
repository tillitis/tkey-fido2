// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include "assert.h"
#include <stdint.h>
#include <stdlib.h>

void exit(int status)
{
	(void)status;

	assert(1 == 2);

	while (1) {
		__asm__("nop");
	}
}
