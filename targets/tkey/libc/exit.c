// Copyright 2024 Tillitis AB

#include "tkey/assert.h"
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
