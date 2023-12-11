#include <string.h>
#include "filesys/cache.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "devices/block.h"
#include "threads/malloc.h"

/* Buffer cache with a maximum capacity of 64 disk blocks */
#define CACHE_SIZE 64

struct cache_block** cache;

int clock_ptr;
struct lock global_cache_lock;

void evict_and_bring(block_sector_t sector) {

  while (true) {
    if (cache[clock_ptr]->ref) {
      clock_ptr = (clock_ptr + 1) % CACHE_SIZE;
      cache[clock_ptr]->ref = false;
    } else {
      //write back
      old_lock_acquire(&cache[clock_ptr]->local_lock);

      if (cache[clock_ptr]->valid && cache[clock_ptr]->dirty) {
        block_write(fs_device, cache[clock_ptr]->sector, &cache[clock_ptr]->data);
      }
      block_read(fs_device, sector, cache[clock_ptr]->data);
      cache[clock_ptr]->valid = true;
      cache[clock_ptr]->dirty = false;
      cache[clock_ptr]->ref = false;
      cache[clock_ptr]->sector = sector;
      old_lock_release(&cache[clock_ptr]->local_lock);
      break;
    }
  }
}

void cache_init() {
  lock_init(&global_cache_lock);
  cache = malloc(sizeof(struct cache_block) * CACHE_SIZE);
  clock_ptr = 0;
  for (int i = 0; i < CACHE_SIZE; i++) {
    cache[i] = malloc(sizeof(struct cache_block));
    cache[i]->dirty = false;
    lock_init(&cache[i]->local_lock);
    cache[i]->valid = false;
    cache[i]->ref = false;
  }
  return;
}

/* Read sector sector into buffer */
void cache_read(block_sector_t sector, uint8_t* buf) {
  // lock_acquire(&global_cache_lock);
  // block_read(fs_device, sector, buf);
  // lock_release(&global_cache_lock);
  old_lock_acquire(&global_cache_lock);
  for (int i = 0; i < CACHE_SIZE; i++) {
    if (cache[i]->sector == sector) {
      old_lock_acquire(&cache[i]->local_lock);
      memcpy(buf, &cache[i]->data, BLOCK_SECTOR_SIZE);
      cache[i]->ref = true;
      old_lock_release(&cache[i]->local_lock);
      old_lock_release(&global_cache_lock);
      return;
    }
  }
  //if not found, we need to evict
  evict_and_bring(sector);
  for (int i = 0; i < CACHE_SIZE; i++) {
    if (cache[i]->sector == sector) {
      old_lock_acquire(&cache[i]->local_lock);
      memcpy(buf, &cache[i]->data, BLOCK_SECTOR_SIZE);
      cache[i]->ref = true;
      old_lock_release(&cache[i]->local_lock);
      old_lock_release(&global_cache_lock);
      return;
    }
  }
  // NOT_REACHED();
  // return;
}

/* write buffer into sector */
void cache_write(block_sector_t sector, uint8_t* buf) {
  // lock_acquire(&global_cache_lock);
  // block_write(fs_device, sector, buf);
  // lock_release(&global_cache_lock);
  old_lock_acquire(&global_cache_lock);
  for (int i = 0; i < CACHE_SIZE; i++) {
    if (cache[i]->sector == sector) {
      old_lock_acquire(&cache[i]->local_lock);
      memcpy(cache[i]->data, buf, BLOCK_SECTOR_SIZE);
      cache[i]->ref = true;
      cache[i]->dirty = true;
      old_lock_release(&cache[i]->local_lock);
      old_lock_release(&global_cache_lock);
      return;
    }
  }

  //if not found, we need to evict
  evict_and_bring(sector);
  for (int i = 0; i < CACHE_SIZE; i++) {
    if (cache[i]->sector == sector) {
      old_lock_acquire(&cache[i]->local_lock);
      memcpy(cache[i]->data, buf, BLOCK_SECTOR_SIZE);
      cache[i]->ref = true;
      cache[i]->dirty = true;
      old_lock_release(&cache[i]->local_lock);
      old_lock_release(&global_cache_lock);
      return;
    }
  }
  //NOT_REACHED();
  return;
}

void flush() {
  old_lock_acquire(&global_cache_lock);
  for (int i = 0; i < CACHE_SIZE; i++) {
    old_lock_acquire(&cache[i]->local_lock);
    if (cache[i]->valid && cache[i]->dirty) {
      block_write(fs_device, cache[i]->sector, &cache[i]->data);
    }
    cache[i]->valid = false;
    cache[i]->dirty = false;
    cache[i]->ref = false;
    old_lock_release(&cache[i]->local_lock);
  }
  old_lock_release(&global_cache_lock);
}

void free_cache() {
  old_lock_acquire(&global_cache_lock);
  for (int i = 0; i < CACHE_SIZE; i++) {
    free(cache[i]);
  }
  free(cache);
  old_lock_release(&global_cache_lock);
}
