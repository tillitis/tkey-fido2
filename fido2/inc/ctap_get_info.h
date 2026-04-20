// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_GET_INFO_H_
#define _CTAP_GET_INFO_H_

#include <stdint.h>

#include "cbor.h"

uint8_t ctap_get_info(CborEncoder *encoder);

#endif
