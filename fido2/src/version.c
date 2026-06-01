// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include "version.h"
#include <assert.h>

const app_version_t app_version = {.major = APP_VERSION_MAJ,
				   .minor = APP_VERSION_MIN,
				   .patch = APP_VERSION_PATCH,
				   .reserved = 0};

// Returns
// negative if a is older than b
// zero if equal
// positive if a is newer than b
int version_compare(const app_version_t *a, const app_version_t *b)
{
	if (a->major != b->major)
		return (int)a->major - (int)b->major;

	if (a->minor != b->minor)
		return (int)a->minor - (int)b->minor;

	return (int)a->patch - (int)b->patch;
}

app_version_t version_get_version(void)
{
	return app_version;
}

static_assert(sizeof(app_version_t) == 4, "sizeof(app_version_t) == 4");
