/*
 * SPDX-FileCopyrightText: 2022 Tillitis AB <tillitis.se>
 * SPDX-License-Identifier: BSD-2-Clause
 */

OUTPUT_ARCH( "riscv" )
ENTRY(_start)

STACK_SIZE = 11K; /* Define stack size */

MEMORY
{
	RAM (rwx)   : ORIGIN = 0x40000000, LENGTH = 0x20000 /* 128 KB */
}

SECTIONS
{
	.text.init :
	{
		*(.text.init)
	} >RAM

	.stack (NOLOAD) :
	{
		. = ALIGN(16);
		_sstack = .;
		. += STACK_SIZE;
		. = ALIGN(16);
		_estack = .;
	} >RAM

	.text :
	{
		. = ALIGN(4);
		_stext = .;
		*(.text)           /* .text sections (code) */
		*(.text*)          /* .text* sections (code) */
		*(.rodata)         /* .rodata sections (constants, strings, etc.) */
		*(.rodata*)        /* .rodata* sections (constants, strings, etc.) */
		*(.srodata)        /* .rodata sections (constants, strings, etc.) */
		*(.srodata*)       /* .rodata* sections (constants, strings, etc.) */
		. = ALIGN(4);
		_etext = .;
		_sidata = _etext;
	} >RAM

	.data : AT (_etext)
	{
		. = ALIGN(4);
		_sdata = .;
		. = ALIGN(4);
		*(.data)           /* .data sections */
		*(.data*)          /* .data* sections */
		. = ALIGN(4);
		_edata = .;
	} >RAM

	.sdata :
	{
		. = ALIGN(4);
		__global_pointer$ = . + 0x800; /* center of small-data region */
		*(.sdata)          /* .sdata sections */
		*(.sdata*)         /* .sdata* sections */
	} >RAM

	.flag :
	{
		*(.flag)           /* .flag sections */
	} >RAM

	/* Uninitialized data section */
	.bss (NOLOAD) :
	{
		. = ALIGN(4);
		_sbss = .;
		*(.bss)
		*(.bss*)
		*(.sbss)
		*(.sbss*)
		*(COMMON)

		. = ALIGN(4);
		_ebss = .;
	} >RAM

}
