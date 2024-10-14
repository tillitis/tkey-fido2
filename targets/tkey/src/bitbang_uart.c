#include <stdint.h>
#include "bitbang_uart.h"

__attribute__ ((optnone)) void bitbang_uart_send_byte(uint32_t byte) {
	// clang-format off
	asm volatile(
			"li t0, 11;" // Bit counter 11 = 8N2
			"li t1, 0xff000028;" // GPIO register address
			"lw t2, 0(t1);" // Load GPIO register value
			"li t4, 0xfffffffb;" // GPIO3 pin mask
			"slli %0, %0, 1;" // Add start bit
			"ori %0, %0, 0b11000000000;" // Add two stop bits
		"next_bit_%=:;"
			// Get next bit
			"andi t3, %0, 1;" // Get least significant bit
			"slli t3, t3, 2;" // Move bit to GPIO3 pin position

			// Update GPIO register
			"and t2, t2, t4;" // Clear pin bit
			"or t2, t2, t3;" // Copy pin bit
			"sw t2, 0(t1);" // Update GPIO register

			// Shift to next bit
			"srli %0, %0, 1;"

			// Adjust baud rate
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;" // 100783 bps

			// Loop if bits left
			"addi t0, t0, -1;"
			"bne t0, zero, next_bit_%=;"
			:
			: "r" (byte)
			: "t0", "t1", "t2", "t3", "t4", "%0", "memory");
	// clang-format on
}

