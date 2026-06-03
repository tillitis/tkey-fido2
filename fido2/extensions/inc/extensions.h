// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef EXTENSIONS_H_
#define EXTENSIONS_H_
#include "apdu.h"
#include "u2f.h"

uint16_t extend_u2f(APDU_HEADER *req, uint8_t *payload, uint32_t len);
void extension_writeback_init(uint8_t *buffer, uint8_t size);
void extension_writeback(uint8_t *buf, uint8_t size);

#endif /* EXTENSIONS_H_ */
