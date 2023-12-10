#ifndef FILESYS_BUFFER_H
#define FILESYS_BUFFER_H

#include <string.h>
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "devices/block.h"
#include "threads/malloc.h"

struct cache_block {
  block_sector_t sector;           /* Sector on disk that this cache is for */
  uint8_t data[BLOCK_SECTOR_SIZE]; /* Raw data from sector in cache */
  struct lock local_lock;          /* Lock for synchronization */
  bool valid;                      /* Valid bit (set false on init, always true after) */
  bool dirty;                      /* Dirty bit */
  bool ref;                        /* Flag for clock algorithm (evict if false) */
};

void cache_init(void);
void cache_read(block_sector_t sector, uint8_t* buf);
void cache_write(block_sector_t sector, uint8_t* buf);
void flush(void);
void free_cache(void);

#endif /* filesys/buffer.h */