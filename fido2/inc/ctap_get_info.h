// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_GET_INFO_H_
#define _CTAP_GET_INFO_H_

#include <stdint.h>

#include "cbor.h"

// clang-format off
/* GET_INFO (0x04) */

// Response structures
#define GI_Resp_versions                         0x01 // Data type: Array of strings
#define GI_Resp_extensions                       0x02 // Data type: Array of strings
#define GI_Resp_aaguid                           0x03 // Data type: Byte String
#define GI_Resp_options                          0x04 // Data type: Map
#define GI_Resp_maxMsgSize                       0x05 // Data type: Unsigned Integer
#define GI_Resp_pinUvAuthProtocols               0x06 // Data type: Array of Unsigned Integers
#define GI_Resp_maxCredentialCountInList         0x07 // Data type: Unsigned Integer
#define GI_Resp_maxCredentialIdLength            0x08 // Data type: Unsigned Integer
#define GI_Resp_transports                       0x09 // Data type: Array of strings
#define GI_Resp_algorithms                       0x0A // Data type: Array of PublicKeyCredentialParameters
#define GI_Resp_maxSerializedLargeBlobArray      0x0B // Data type: Unsigned Integer
#define GI_Resp_forcePINChange                   0x0C // Data type: Boolean
#define GI_Resp_minPINLength                     0x0D // Data type: Unsigned Integer
#define GI_Resp_firmwareVersion                  0x0E // Data type: Unsigned Integer
#define GI_Resp_maxCredBlobLength                0x0F // Data type: Unsigned Integer
#define GI_Resp_maxRPIDsForSetMinPINLength       0x10 // Data type: Unsigned Integer
#define GI_Resp_preferredPlatformUvAttempts      0x11 // Data type: Unsigned Integer. (CBOR major type 0)
#define GI_Resp_uvModality                       0x12 // Data type: Unsigned Integer. (CBOR major type 0)
#define GI_Resp_certifications                   0x13 // Data type: Map
#define GI_Resp_remainingDiscoverableCredentials 0x14 // Data type: Unsigned Integer
#define GI_Resp_vendorPrototypeConfigCommands    0x15 // Data type: Array of Unsigned Integers

// clang-format on

uint8_t ctap_get_info(CborEncoder *encoder);

#endif
