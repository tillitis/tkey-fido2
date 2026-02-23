// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _FS_H_
#define _FS_H_

#include <lfs.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LFS_CACHE_SIZE 1024

typedef struct {
	lfs_file_t file;
	struct lfs_file_config cfg;
	uint8_t buf[LFS_CACHE_SIZE];
	bool open;
} fs_file_t;

int fs_init(void);

int fs_open_file(fs_file_t *f, const char *name, int flags);
int fs_close_file(fs_file_t *f);
int fs_file_size(fs_file_t *f);

int fs_read(fs_file_t *f, void *buf, size_t len);
int fs_read_at(fs_file_t *f, void *buf, size_t len, size_t offset);
int fs_write(fs_file_t *f, const void *buf, size_t len);
int fs_write_at(fs_file_t *f, const void *buf, size_t len, int offset);

int fs_read_open(const char *name, void *buf, size_t len, int offset);
int fs_write_open(const char *name, const void *buf, size_t len, int offset);

int fs_dir_del(const char *dir_name);
int fs_dir_nr_files(const char *dir_name);
int fs_create_dir(const char *dir_name);
int fs_truncate_file(fs_file_t *f, size_t size);

#endif
