// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _LOG_H
#define _LOG_H

#include <stddef.h>
#include <stdint.h>

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 0
#endif

#define ENABLE_FILE_LOGGING

void LOG(uint32_t tag, const char *filename, int num, const char *fmt, ...);
void LOG_HEX(uint32_t tag, const uint8_t *data, size_t length);

// clang-format off
typedef enum {
	TAG_GEN      = (1 <<  0),  /* Generic                     */
	TAG_MC       = (1 <<  1),  /* Make Credential             */
	TAG_GA       = (1 <<  2),  /* Get Assertion               */
	TAG_CP       = (1 <<  3),  /* Client Pin                  */
	TAG_ERR      = (1 <<  4),  /* Error                       */
	TAG_PARSE    = (1 <<  5),  /* Parsing                     */
	TAG_CTAP     = (1 <<  6),  /* CTAP data                   */
	TAG_U2F      = (1 <<  7),  /* U2F data                    */
	TAG_DUMP     = (1 <<  8),  /* Dump data                   */
	TAG_GREEN    = (1 <<  9),  /* Information                 */
	TAG_RED      = (1 << 10),  /* Warnings                    */
	TAG_TIME     = (1 << 11),  /* Timestamps                  */
	TAG_HID      = (1 << 12),  /* Human Interface Device      */
	TAG_BE       = (1 << 13),  /* Bio Enrollment              */
	TAG_STOR     = (1 << 15),  /* Storage status              */
	TAG_DUMP2    = (1 << 16),  /* Unused                      */
	TAG_BOOT     = (1 << 17),  /* Unused                      */
	TAG_EXT      = (1 << 18),  /* Extension (U2F)             */
	TAG_CCID     = (1 << 21),  /* Unused                      */
	TAG_CM       = (1 << 22),  /* Credential Management       */
	TAG_COUNT    = (1 << 23),
	TAG_PROF     = (1 << 24),

	TAG_NO_TAG   = (1UL << 30),
	TAG_FILENO   = (1UL << 31)
} LOG_TAG;
// clang-format on

#if defined(DEBUG_LEVEL) && DEBUG_LEVEL > 0

void set_logging_mask(uint32_t mask);
#define printf1(tag, fmt, ...)                                                 \
	LOG(tag & ~(TAG_FILENO), NULL, 0, fmt, ##__VA_ARGS__)
#define printf2(tag, fmt, ...)                                                 \
	LOG(tag | TAG_FILENO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define printf3(tag, fmt, ...)                                                 \
	LOG(tag | TAG_FILENO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define dump_hex1(tag, data, len) LOG_HEX(tag, data, len)

uint32_t timestamp(void);

extern uint32_t fido2_log_profile_indent_level;
/**
 * Begin a new profiling measurement
 *
 * Opens a new scope for profiling. Measuring is ended using PROFILE_END.
 * PROFILE_BEGIN-PROFILE_END blocks can be nested.
 */
#define PROFILE_BEGIN                                                          \
	{                                                                      \
		uint32_t fido2_log_profile_start_line = __LINE__;              \
		uint32_t fido2_log_profile_start_time = millis();              \
		fido2_log_profile_indent_level++;

/**
 * End a profiling measurement
 *
 * Closes a profiling scope. The time spent inside the scope is logged. An
 * optional message (msg) can be added to the log line.
 */
#define PROFILE_END(msg)                                                       \
	fido2_log_profile_indent_level--;                                      \
	LOG_PROFILE(msg, fido2_log_profile_indent_level,                       \
		    millis() - fido2_log_profile_start_time, __FILE__,         \
		    fido2_log_profile_start_line, __LINE__);                   \
	}

void LOG_PROFILE(const char *msg, uint8_t indent_level, uint32_t duration_ms,
		 const char *filename, uint32_t start_line, uint32_t end_line);

#else

#define set_logging_mask(mask)
#define printf1(tag, fmt, ...)
#define printf2(tag, fmt, ...)
#define printf3(tag, fmt, ...)
#define dump_hex1(tag, data, len)
#define timestamp()

#define PROFILE_BEGIN
#define PROFILE_END(msg)

#endif

#endif
