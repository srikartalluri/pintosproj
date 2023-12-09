#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "filesys/directory.h"
#include "filesys/file.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0 /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1 /* Root directory file inode sector. */

/* Block device that contains the file system. */
extern struct block* fs_device;

bool filesys_mkdir(const char* name);
void filesys_init(bool format);
void filesys_done(void);
bool filesys_create(const char* name, off_t initial_size);
bool filesys_open(const char* name, struct file** file_ret, struct dir** dir_ret);
bool filesys_remove(const char* name);

#endif /* filesys/filesys.h */
