// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdint.h>
#include <tkey/syscall.h>

#include "fs.h"
#include "lfs.h"
#include "printf-emb.h"

// Flash parameters
#define LFS_READ_SIZE 256
#define LFS_PROG_SIZE 256
#define LFS_BLOCK_SIZE 4096
#define LFS_BLOCK_COUNT 32
#define LFS_LOOKAHEAD_SIZE 16

// Static memory
static uint8_t read_buffer[LFS_CACHE_SIZE] = {0};
static uint8_t prog_buffer[LFS_CACHE_SIZE] = {0};
static uint8_t lookahead_buffer[LFS_LOOKAHEAD_SIZE] = {0};

// Flash I/O callbacks
static int lfs_read_wrapper(const struct lfs_config *c, lfs_block_t block,
			    lfs_off_t off, void *buffer, lfs_size_t size)
{
	uint32_t abs_offset = block * c->block_size + off;
	int ret = sys_read(abs_offset, buffer, size);
	if (ret < 0)
		return ret; // map your error to negative
	return 0;	    // success
}

static int lfs_prog_wrapper(const struct lfs_config *c, lfs_block_t block,
			    lfs_off_t off, const void *buffer, lfs_size_t size)
{
	uint32_t abs_offset = (block * c->block_size) + off;

	// Safety check for 128KB limit
	if (abs_offset + size > 128 * 1024)
		return LFS_ERR_NOSPC;

	// With prog_size=256, off is always % 256 == 0 and size is always % 256
	// == 0
	if (sys_write(abs_offset, (void *)buffer, size) != 0) {
		return LFS_ERR_IO;
	}
	return LFS_ERR_OK;
}

static int lfs_erase_wrapper(const struct lfs_config *c, lfs_block_t block)
{
	uint32_t abs_offset = block * c->block_size;

	// Must erase multiples of 4096 bytes
	if (c->block_size % 4096 != 0)
		return -1; // unsupported configuration

	int ret = sys_erase(abs_offset, c->block_size);
	return (ret < 0) ? -1 : 0;
}

static int lfs_sync_wrapper(const struct lfs_config *c)
{
	(void)c; // unused
	return 0;
}

// lfs config
static const struct lfs_config cfg = {
    // block device operations
    .read = lfs_read_wrapper,
    .prog = lfs_prog_wrapper,
    .erase = lfs_erase_wrapper,
    .sync = lfs_sync_wrapper,

    // block device configuration
    .read_size = LFS_READ_SIZE,
    .prog_size = LFS_PROG_SIZE,
    .block_size = LFS_BLOCK_SIZE,
    .block_count = LFS_BLOCK_COUNT,

    .cache_size = LFS_CACHE_SIZE,
    .lookahead_size = LFS_LOOKAHEAD_SIZE,

    .read_buffer = read_buffer,
    .prog_buffer = prog_buffer,
    .lookahead_buffer = lookahead_buffer,

    // Number of erase cycles before littlefs evicts metadata logs and moves
    // the metadata to another block. Suggested values are in the
    // range 100-1000, with large values having better performance at the cost
    // of less consistent wear distribution.
    .block_cycles = 1000,
};

static lfs_t lfs = {0};

int fs_init(void)
{
	int err = 0;

	// Allocate a flash area
	err = sys_alloc();
	if (err) {
		return err;
	}

	// Mount the filesystem
	err = lfs_mount(&lfs, &cfg);

	// Reformat if we can't mount the filesystem,
	// this should only happen on the first boot
	if (err) {
		lfs_format(&lfs, &cfg);
		err = lfs_mount(&lfs, &cfg);
	}
	return err;
}

// Opens and reads the file *name, if it exists, from start offset, and then
// closes it. Returns number of bytes read or negative on error.
int fs_read_open(const char *name, void *buf, size_t len, int offset)
{
	lfs_file_t file;
	struct lfs_file_config config = {0x00};
	uint8_t file_buf[LFS_CACHE_SIZE];
	config.buffer = file_buf;

	int ret;

	ret = lfs_file_opencfg(&lfs, &file, name, LFS_O_RDONLY, &config);
	if (ret < 0) {
		return ret;
	}

	lfs_soff_t size = lfs_file_size(&lfs, &file);
	if (size < offset) {
		// Record does not exist
		return 0;
	}

	lfs_file_seek(&lfs, &file, offset, LFS_SEEK_SET);

	ret = lfs_file_read(&lfs, &file, buf, len);
	lfs_file_close(&lfs, &file);

	return ret;
}

// Opens and writes to the file *name, from start offset. Creates the file if it
// does not exists. Closes the file once done. Returns number of bytes written
// or negative on error.
int fs_write_open(const char *name, const void *buf, size_t len, int offset)
{

	lfs_file_t file;
	struct lfs_file_config config = {0x00};
	uint8_t file_buf[LFS_CACHE_SIZE];

	config.buffer = file_buf;

	int ret = 0;
	lfs_file_opencfg(&lfs, &file, name, LFS_O_RDWR | LFS_O_CREAT, &config);
	lfs_file_seek(&lfs, &file, offset, LFS_SEEK_SET);
	ret = lfs_file_write(&lfs, &file, buf, len);
	lfs_file_close(&lfs, &file);

	return ret;
}

// Opens a file of *name, with flags.
// Returns zero on success, negative on error.
int fs_open_file(fs_file_t *f, const char *name, int flags)
{
	if (f == NULL) {
		return -2;
	}

	// File is already open
	if (f->open) {
		return -1;
	}

	memset(&f->cfg, 0, sizeof(f->cfg));
	f->cfg.buffer = f->buf;

	int ret = lfs_file_opencfg(&lfs, &f->file, name, flags, &f->cfg);
	if (ret == 0) {
		f->open = true;
	}
	return ret;
}

// Opens the file *f.
// Returns zero on success, negative on error.
int fs_close_file(fs_file_t *f)
{
	if (f == NULL) {
		return -2;
	}

	if (!f->open) {
		return -1;
	}

	int ret = lfs_file_close(&lfs, &f->file);
	if (ret == 0) {
		f->open = false;
	}
	return ret;
}

int fs_file_size(fs_file_t *f)
{
	if (f == NULL) {
		return -2;
	}

	if (!f->open) {
		return -1;
	}

	return lfs_file_size(&lfs, &f->file);
}

int fs_truncate_file(fs_file_t *f, size_t size)
{
	if (f == NULL) {
		return -2;
	}

	if (!f->open) {
		return -1;
	}

	lfs_file_truncate(&lfs, &f->file, size);
	return 0;
}

// Reads from an already open file *f, len bytes starting from last file
// position to *buf. Returns bytes read, or negavtive on error.
int fs_read(fs_file_t *f, void *buf, size_t len)
{
	if (f == NULL) {
		return -2;
	}

	if (!f->open) {
		return -1;
	}

	return lfs_file_read(&lfs, &f->file, buf, len);
}

// Reads from an already open file *f, len bytes starting from offset to
// *buf. Returns bytes read, or negavtive on error.
int fs_read_at(fs_file_t *f, void *buf, size_t len, size_t offset)
{
	if (f == NULL) {
		return -2;
	}

	if (!f->open) {
		return -1;
	}

	lfs_file_seek(&lfs, &f->file, offset, LFS_SEEK_SET);
	return lfs_file_read(&lfs, &f->file, buf, len);
}

// Writes to an already open file *f, writing to offset from *buf len
// bytes. Returns bytes written, or negavtive on error.
int fs_write_at(fs_file_t *f, const void *buf, size_t len, int offset)
{
	if (f == NULL) {
		return -2;
	}

	if (!f->open) {
		return -1;
	}

	lfs_file_seek(&lfs, &f->file, offset, LFS_SEEK_SET);
	return lfs_file_write(&lfs, &f->file, buf, len);
}

// Appending write to an already open file *f from *buf len
// bytes. Returns bytes written, or negavtive on error.
int fs_write(fs_file_t *f, const void *buf, size_t len)
{
	if (f == NULL) {
		return -2;
	}

	if (!f->open) {
		return -1;
	}

	return lfs_file_write(&lfs, &f->file, buf, len);
}

// Returns number of files in the folder *dir_name.
// Returns negative on error, or if the folder does not exist.
int fs_dir_nr_files(const char *dir_name)
{
	if (!dir_name || !dir_name[0]) {
		return -2;
	}

	lfs_dir_t dir;
	struct lfs_info info;
	int count = 0;

	int ret = lfs_dir_open(&lfs, &dir, dir_name);
	if (ret < 0) {
		return ret;
	}

	while (true) {
		ret = lfs_dir_read(&lfs, &dir, &info);
		if (ret < 0) {
			lfs_dir_close(&lfs, &dir);
			return ret;
		}

		if (ret == 0) {
			// End of directory
			break;
		}

		if (info.type == LFS_TYPE_REG) {
			count++;
		}
	}

	lfs_dir_close(&lfs, &dir);
	return count;
}

// Deletes all files underneath the folder *dir_name.
// Returns negative on error.
int fs_dir_del(const char *dir_name)
{

	// Check for NULL or empty string
	if (!dir_name || !dir_name[0]) {
		return -2;
	}

	lfs_dir_t dir;
	struct lfs_info info;

	int ret = lfs_dir_open(&lfs, &dir, dir_name);
	if (ret < 0) {
		// Directory does not exist
		return ret;
	}

	while (true) {
		ret = lfs_dir_read(&lfs, &dir, &info);
		if (ret < 0) {
			lfs_dir_close(&lfs, &dir);
			return ret;
		}

		if (ret == 0) {
			// End of directory
			break;
		}

		size_t dir_len = strlen(dir_name);
		size_t name_len = strlen(info.name);
		char path[dir_len + 1 + name_len +
			  1]; // dir + '/ ' + file + null
		snprintf(path, sizeof(path), "%s/%s", dir_name, info.name);

		// Only remove files
		if (info.type == LFS_TYPE_REG) {
			ret = lfs_remove(&lfs, path);
			if (ret < 0) {
				lfs_dir_close(&lfs, &dir);
				return ret;
			}
		}
	}

	lfs_dir_close(&lfs, &dir);
	return 0;
}

// Creates a directory, returns zero on success.
// Does not treat an existing dir as an error.
int fs_create_dir(const char *dir_name)
{
	if (!dir_name || !dir_name[0]) {
		return -2;
	}

	int ret = lfs_mkdir(&lfs, dir_name);
	if (ret < 0 && ret != LFS_ERR_EXIST) {
		return ret;
	}
	return 0;
}
