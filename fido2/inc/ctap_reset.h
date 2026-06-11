// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_RESET_H_
#define _CTAP_RESET_H_

#include "ctap_errors.h"

CtapStatus ctap_reset(void);
void ctap_reset_state(void);

#endif
