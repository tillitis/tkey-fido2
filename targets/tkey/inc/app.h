// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
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
// #define ENABLE_WALLET

#define ENABLE_U2F

// #define DISABLE_CTAPHID_PING
// #define DISABLE_CTAPHID_WINK
// #define DISABLE_CTAPHID_CBOR

void hw_init();

// Return 1 if Solo is secure/locked.
int solo_is_locked();

// #define TEST
// #define TEST_POWER

#endif
