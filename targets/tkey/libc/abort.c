// Copyright 2024 Tillitis AB

#include "tkey/assert.h"
#include <stdlib.h>

void abort(void)
{
	assert(1 == 2);

	while (1) {
		__asm__("nop");
	}
}
