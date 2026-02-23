// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _APP_H_
#define _APP_H_
#include "solo.h"
#include "version.h"
#include <stdint.h>

#define SOLO

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 0
#endif

// #define ENABLE_U2F_EXTENSIONS

#define ENABLE_U2F

// #define DISABLE_CTAPHID_PING
// #define DISABLE_CTAPHID_WINK
// #define DISABLE_CTAPHID_CBOR

void hw_init();

// #define TEST
// #define TEST_POWER

#endif
