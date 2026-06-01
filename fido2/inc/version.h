// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _VERSION_H_
#define _VERSION_H_

#include <stdbool.h>
#include <stdint.h>

// Version can be set here, or via make by defining _MAJ, _MIN and _PATCH.
#ifndef APP_VERSION_MAJ
#define APP_VERSION_MAJ 0
#endif

#ifndef APP_VERSION_MIN
#define APP_VERSION_MIN 0
#endif

#ifndef APP_VERSION_PATCH
#define APP_VERSION_PATCH 0
#endif

typedef struct {
	union {
		uint32_t raw;
		struct {
			uint8_t major;
			uint8_t minor;
			uint8_t patch;
			uint8_t reserved;
		};
	};
} app_version_t;

int version_compare(const app_version_t *a, const app_version_t *b);
app_version_t version_get_version(void);

#endif
