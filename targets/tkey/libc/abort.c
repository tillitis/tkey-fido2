// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include "tkey/assert.h"
#include <stdlib.h>

void abort(void)
{
	assert(1 == 2);

	while (1) {
		__asm__("nop");
	}
}
