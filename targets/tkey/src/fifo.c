// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include "fifo.h"
#include <stdint.h>
#include <string.h>

// FIFO_CREATE(debug,4096,1)
// FIFO_CREATE(hidmsg,100,64)

#define MSG_SIZE 64
#define NR_OF_MSG 10

int hidmsg_write_ptr = 0;
int hidmsg_read_ptr = 0;
int hidmsg_size = 0;
static uint8_t hidmsg_write_buf[MSG_SIZE * NR_OF_MSG];

int fifo_hidmsg_add(uint8_t *msg);
int fifo_hidmsg_take(uint8_t *msg);
uint32_t fifo_hidmsg_size();
uint32_t fifo_hidmsg_rhead();
uint32_t fifo_hidmsg_whead();

int fifo_hidmsg_add(uint8_t *msg)
{
	if (hidmsg_size < NR_OF_MSG) {
		memmove(hidmsg_write_buf + hidmsg_write_ptr * MSG_SIZE, msg,
			MSG_SIZE);
		hidmsg_write_ptr++;
		if (hidmsg_write_ptr >= NR_OF_MSG)
			hidmsg_write_ptr = 0;
		hidmsg_size++;
		return 0;
	}
	return -1;
}

int fifo_hidmsg_take(uint8_t *msg)
{
	memmove(msg, hidmsg_write_buf + hidmsg_read_ptr * MSG_SIZE, MSG_SIZE);
	if (hidmsg_size > 0) {
		hidmsg_read_ptr++;
		if (hidmsg_read_ptr >= NR_OF_MSG)
			hidmsg_read_ptr = 0;
		hidmsg_size--;
		return 0;
	}
	return -1;
}

uint32_t fifo_hidmsg_size()
{
	return (hidmsg_size);
}
uint32_t fifo_hidmsg_rhead()
{
	return (hidmsg_read_ptr);
}
uint32_t fifo_hidmsg_whead()
{
	return (hidmsg_write_ptr);
}
