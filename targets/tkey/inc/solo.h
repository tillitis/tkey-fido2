#ifndef _SOLO_H_
#define _SOLO_H_

#include <stdint.h>

void device_init();

void usbhid_init();
void usbhid_close();
int usbhid_recv(uint8_t *msg);

void boot_solo_bootloader();

void delay(uint32_t ms);

#endif
