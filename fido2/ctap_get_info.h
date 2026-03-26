// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_GET_INFO_H
#define _CTAP_GET_INFO_H

#include "cbor.h"
#include <stdint.h>

#define RESP_versions 0x1
#define RESP_extensions 0x2
#define RESP_aaguid 0x3
#define RESP_options 0x4
#define RESP_maxMsgSize 0x5
#define RESP_pinUvAuthProtocols 0x6
#define RESP_maxCredentialCountInList 0x7
#define RESP_maxCredentialIdLength 0x8
#define RESP_transport 0x9
#define RESP_algorithms 0xA

uint8_t ctap_get_info(CborEncoder *encoder);
#endif
