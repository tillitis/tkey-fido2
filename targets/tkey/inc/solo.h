// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _SOLO_H_
#define _SOLO_H_

#include <stdint.h>

void device_init();

void usbhid_init();
void usbhid_close();
int usbhid_recv(uint8_t *msg);

void delay(uint32_t ms);

#endif
