// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_GET_NEXT_ASSERTION_H_
#define _CTAP_GET_NEXT_ASSERTION_H_

#include <stdint.h>

#include "cbor.h"

uint8_t ctap_get_next_assertion(CborEncoder *encoder);

#endif
