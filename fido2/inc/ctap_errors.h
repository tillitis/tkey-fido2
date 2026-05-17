// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_ERRORS_H_
#define _CTAP_ERRORS_H_

// CTAP 2.1 defines, Proposed Standard, June 21, 2022

// clang-format off
typedef enum {
    CTAP1_ERR_SUCCESS                 = 0x00,
    CTAP2_OK                          = 0x00,
    CTAP1_ERR_INVALID_COMMAND         = 0x01,
    CTAP1_ERR_INVALID_PARAMETER       = 0x02,
    CTAP1_ERR_INVALID_LENGTH          = 0x03,
    CTAP1_ERR_INVALID_SEQ             = 0x04,
    CTAP1_ERR_TIMEOUT                 = 0x05,
    CTAP1_ERR_CHANNEL_BUSY            = 0x06,
    CTAP1_ERR_LOCK_REQUIRED           = 0x0A,
    CTAP1_ERR_INVALID_CHANNEL         = 0x0B,
    CTAP2_ERR_CBOR_UNEXPECTED_TYPE    = 0x11,
    CTAP2_ERR_INVALID_CBOR            = 0x12,
    CTAP2_ERR_MISSING_PARAMETER       = 0x14,
    CTAP2_ERR_LIMIT_EXCEEDED          = 0x15,
    CTAP2_ERR_FP_DATABASE_FULL        = 0x17,
    CTAP2_ERR_LARGE_BLOB_STORAGE_FULL = 0x18,
    CTAP2_ERR_CREDENTIAL_EXCLUDED     = 0x19,
    CTAP2_ERR_PROCESSING              = 0x21,
    CTAP2_ERR_INVALID_CREDENTIAL      = 0x22,
    CTAP2_ERR_USER_ACTION_PENDING     = 0x23,
    CTAP2_ERR_OPERATION_PENDING       = 0x24,
    CTAP2_ERR_NO_OPERATIONS           = 0x25,
    CTAP2_ERR_UNSUPPORTED_ALGORITHM   = 0x26,
    CTAP2_ERR_OPERATION_DENIED        = 0x27,
    CTAP2_ERR_KEY_STORE_FULL          = 0x28,
    CTAP2_ERR_UNSUPPORTED_OPTION      = 0x2B,
    CTAP2_ERR_INVALID_OPTION          = 0x2C,
    CTAP2_ERR_KEEPALIVE_CANCEL        = 0x2D,
    CTAP2_ERR_NO_CREDENTIALS          = 0x2E,
    CTAP2_ERR_USER_ACTION_TIMEOUT     = 0x2F,
    CTAP2_ERR_NOT_ALLOWED             = 0x30,
    CTAP2_ERR_PIN_INVALID             = 0x31,
    CTAP2_ERR_PIN_BLOCKED             = 0x32,
    CTAP2_ERR_PIN_AUTH_INVALID        = 0x33,
    CTAP2_ERR_PIN_AUTH_BLOCKED        = 0x34,
    CTAP2_ERR_PIN_NOT_SET             = 0x35,
    CTAP2_ERR_PUAT_REQUIRED           = 0x36,
    CTAP2_ERR_PIN_POLICY_VIOLATION    = 0x37,
    /* Reserved for Future Use        = 0x38, */
    CTAP2_ERR_REQUEST_TOO_LARGE       = 0x39,
    CTAP2_ERR_ACTION_TIMEOUT          = 0x3A,
    CTAP2_ERR_UP_REQUIRED             = 0x3B,
    CTAP2_ERR_UV_BLOCKED              = 0x3C,
    CTAP2_ERR_INTEGRITY_FAILURE       = 0x3D,
    CTAP2_ERR_INVALID_SUBCOMMAND      = 0x3E,
    CTAP2_ERR_UV_INVALID              = 0x3F,
    CTAP2_ERR_UNAUTHORIZED_PERMISSION = 0x40,
    CTAP1_ERR_OTHER                   = 0x7F,
    CTAP2_ERR_SPEC_LAST               = 0xDF,
    CTAP2_ERR_EXTENSION_FIRST         = 0xE0,
    CTAP2_ERR_EXTENSION_LAST          = 0xEF,
    CTAP2_ERR_VENDOR_FIRST            = 0xF0,
    CTAP2_ERR_VENDOR_LAST             = 0xFF,
} CtapError;
// clang-format on

typedef struct {
	CtapError value;
} CtapStatus;

const char *ctap_error_string(CtapStatus error);

#endif
