#ifndef FRAME_H
#define FRAME_H

#include <stdint.h>

#define MAX_FRAME_SIZE         64
#define HID_FRAME_SIZE         64
#define MAX_CDC_FRAME_SIZE     64

#define MODE_CDC        0x40
#define MODE_CDC_ACK    0x02
#define MODE_HID        0x80
#define MODE_HID_ACK    0x08

struct header {
    uint8_t mode;
    uint8_t len;
};

struct frame {
    struct header hdr;            // Framing Protocol header
    uint8_t data[MAX_FRAME_SIZE]; // Application level protocol
};

#endif
