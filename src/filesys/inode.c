#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <stdbool.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define DIRECT 124
#define INDIRECT 128
#define MAX_SIZE 8388608
/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  block_sector_t direct[124]; /* First data sector. */
  block_sector_t indirect;
  block_sector_t doubly_indirect;
  off_t length;   /* File size in bytes. */
  unsigned magic; /* Magic number. */
};

/* In-memory inode. */
struct inode {
  struct list_elem elem; /* Element in inode list. */
  block_sector_t sector; /* Sector number of disk location. */
  int open_cnt;          /* Number of openers. */
  bool removed;          /* True if deleted, false otherwise. */
  int deny_write_cnt;    /* 0: writes ok, >0: deny writes. */
  struct lock inode_lock;
};

struct lock freemap_lock;
/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

// classifies what type of pointer to use
enum { CLASS_DIRECT, CLASS_INDIRECT, CLASS_DOUBLY_INDIRECT, CLASS_TOO_BIG } byte_class_t;

int get_byte_class(off_t block_id) {
  if (block_id < DIRECT) {
    return CLASS_DIRECT;
  } else if (block_id < INDIRECT) {
    return CLASS_INDIRECT;
  } else if (block_id < INDIRECT * INDIRECT) {
    return CLASS_DOUBLY_INDIRECT;
  } else {
    return CLASS_TOO_BIG;
  }
}

/* Get block_sector_t for position pos for a given inode */
block_sector_t byte_to_sector(struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);

  struct inode_disk* inode_disk = malloc(sizeof(struct inode_disk));
  cache_read(inode->sector, inode_disk);

  if (pos >= inode_disk->length || pos < 0) {
    NOT_REACHED();
  }

  /* Convert the byte position to a block index */
  off_t block_index = pos / BLOCK_SECTOR_SIZE;

  /* Bases and limits of direct pointers, indirect pointer, and doubly indirect pointer*/
  off_t direct_base = 0;
  off_t direct_limit = direct_base + DIRECT;
  off_t indirect_limit = direct_limit + INDIRECT;
  off_t doubly_indirect_limit = indirect_limit + INDIRECT * INDIRECT;

  //now we need to go through the torturous porcedure of doing everything - first if we just do direct pointers
  if (block_index < direct_limit) {
    block_sector_t to_ret = inode_disk->direct[block_index];
    free(inode_disk);
    return to_ret;
  } else if (block_index >= direct_limit && block_index < indirect_limit) {
    //get the pointer sheet by cache read
    block_sector_t* pointer_sheet = malloc(BLOCK_SECTOR_SIZE);
    cache_read(inode_disk->indirect, pointer_sheet);
    int indirect_idx = block_index - DIRECT;
    block_sector_t to_ret = pointer_sheet[indirect_idx];
    free(inode_disk);
    free(pointer_sheet);
    return to_ret;
  } else if (block_index >= indirect_limit && block_index < MAX_SIZE / BLOCK_SECTOR_SIZE) {
    //okay this is the hard part. We need to bring in the double sheet and then the single sheet. We then index through them to get the sector we need to write to/read from
    block_sector_t* primary_sheet = malloc(BLOCK_SECTOR_SIZE);
    cache_read(inode_disk->doubly_indirect, primary_sheet);
    int primary_idx = (block_index - DIRECT - INDIRECT) / INDIRECT;
    block_sector_t* sec_sheet = malloc(BLOCK_SECTOR_SIZE);
    cache_read(primary_sheet[primary_idx], sec_sheet);
    int sec_idx = block_index - DIRECT - INDIRECT - primary_idx * INDIRECT;
    block_sector_t to_ret = sec_sheet[sec_idx];
    free(inode_disk);
    free(sec_sheet);
    free(primary_sheet);
    return to_ret;
  } else {
    NOT_REACHED();
  }
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. 
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  if (pos < inode->data.length)
    return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  else
    return -1;
} */

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

uint8_t* zero_buffer;
int num_inodes_on_disk;

/* Initializes the inode module. */
void inode_init(void) {
  list_init(&open_inodes);
  cache_init();
  lock_init(&freemap_lock);

  num_inodes_on_disk = 0;
  zero_buffer = malloc(BLOCK_SECTOR_SIZE);
  memset(zero_buffer, 0, BLOCK_SECTOR_SIZE);
}

void inode_end(void) { free(zero_buffer); }

static bool inode_resize(struct inode_disk*, off_t length);

/* handles releasing of locks upon failure */
bool try_allocate(block_sector_t* block_ptr, struct inode_disk* inode) {
  if (!free_map_allocate(1, block_ptr)) {
    old_lock_release(&freemap_lock);
    inode_resize(inode, inode->length);
    return false;
  }
  cache_write(*block_ptr, zero_buffer);

  return true;
}

/* Expands inode to become length long */
static bool inode_resize(struct inode_disk* inode, off_t length) {
  // handle direct pointers
  old_lock_acquire(&freemap_lock);
  for (off_t i = 0; i < DIRECT; i++) {
    if (length <= BLOCK_SECTOR_SIZE * i && inode->direct[i] != 0) {
      // shrink
      free_map_release(inode->direct[i], 1);
      inode->direct[i] = 0;
    } else if (length > BLOCK_SECTOR_SIZE * i && inode->direct[i] == 0) {
      // grow
      if (!try_allocate(&inode->direct[i], inode))
        return false;
    }
  }
  // handle indirect pointers
  block_sector_t* buffer = malloc(sizeof(block_sector_t) * INDIRECT);
  memset(buffer, 0, INDIRECT * sizeof(block_sector_t));

  if (inode->indirect == 0) {
    if (length > (DIRECT)*BLOCK_SECTOR_SIZE && !try_allocate(&inode->indirect, inode)) {
      free(buffer);
      return false;
    }
  } else {
    cache_read(inode->indirect, buffer);
  }

  for (off_t i = 0; i < INDIRECT; i++) {
    if (length <= (DIRECT + i) * BLOCK_SECTOR_SIZE && buffer[i] != 0) {
      free_map_release(buffer[i], 1);
      buffer[i] = 0;
    } else if (length > (DIRECT + i) * BLOCK_SECTOR_SIZE && buffer[i] == 0) {
      if (!try_allocate(&buffer[i], inode)) {
        free(buffer);
        return false;
      }
    }
  }

  if (length <= (DIRECT * BLOCK_SECTOR_SIZE) && inode->indirect != 0) {
    // no indirect pointers
    free_map_release(inode->indirect, 1);
    inode->indirect = 0;
  } else if (inode->indirect != 0) {
    // using indirect pointers
    cache_write(inode->indirect, buffer);
  }

  // handle doubly indirect pointers
  memset(buffer, 0, INDIRECT * sizeof(block_sector_t));

  if (inode->doubly_indirect == 0) {
    if (length > (DIRECT + INDIRECT) * BLOCK_SECTOR_SIZE &&
        !try_allocate(&inode->doubly_indirect, inode)) {
      free(buffer);
      return false;
    }
  } else {
    cache_read(inode->doubly_indirect, buffer);
  }

  for (off_t i = 0; i < INDIRECT; i++) {
    off_t first_byte_value = (DIRECT + INDIRECT + i * INDIRECT) * BLOCK_SECTOR_SIZE;

    if (length <= first_byte_value && buffer[i] != 0) {
      free_map_release(buffer[i], 1);
      buffer[i] = 0;
    } else if (length > first_byte_value) {
      block_sector_t* buffer_b = malloc(sizeof(block_sector_t) * INDIRECT);
      memset(buffer_b, 0, INDIRECT * sizeof(block_sector_t));

      if (buffer[i] == 0) {
        if (!try_allocate(&buffer[i], inode)) {
          free(buffer);
          free(buffer_b);
          return false;
        }
      } else {
        cache_read(buffer[i], buffer_b);
      }

      for (off_t j = 0; j < INDIRECT; j++) {
        off_t byte_value = (DIRECT + INDIRECT + i * INDIRECT + j) * BLOCK_SECTOR_SIZE;
        if (length <= byte_value && buffer_b[j] != 0) {
          free_map_release(buffer_b[j], 1);
          buffer_b[j] = 0;
        } else if (length > byte_value && buffer_b[j] == 0) {
          if (!try_allocate(buffer_b[i], inode)) {
            free(buffer);
            free(buffer_b);
            return false;
          }
        }
      }

      if (length <= (DIRECT + INDIRECT + i * INDIRECT) * BLOCK_SECTOR_SIZE && buffer[i] != 0) {
        free_map_release(buffer[i], 1);
        buffer[i] = 0;
      } else if (buffer[i] != 0) {
        cache_write(buffer[i], buffer_b);
      }
      free(buffer_b);
    }
  }

  if (inode->doubly_indirect != 0 && length <= (DIRECT + INDIRECT) * BLOCK_SECTOR_SIZE) {
    free_map_release(inode->doubly_indirect, 1);
    inode->indirect = 0;
  } else if (inode->doubly_indirect != 0) {
    cache_write(inode->doubly_indirect, buffer);
  }

  // handle doubly indirect pointers
  old_lock_release(&freemap_lock);
  free(buffer);
  return true;
}

const int MAX_NUM_INODES = 500;

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  if (num_inodes_on_disk >= MAX_NUM_INODES)
    return false;

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);
  disk_inode = calloc(BLOCK_SECTOR_SIZE, 1);
  cache_read(sector, disk_inode);

  disk_inode->length = 0;
  disk_inode->magic = INODE_MAGIC;
  success = inode_resize(disk_inode, length);
  disk_inode->length = length;

  cache_write(sector, disk_inode);
  free(disk_inode);
  num_inodes_on_disk++;
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);
    uint8_t* buf = malloc(BLOCK_SECTOR_SIZE);
    /* Deallocate blocks if removed. */
    if (inode->removed) {
      cache_read(inode->sector, buf);
      inode_resize(buf, 0);
      free_map_release(inode->sector, 1);
      num_inodes_on_disk--;
    }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t* bounce = NULL;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    if (offset >= inode_length(inode)) {
      break;
    }
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      cache_read(sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      cache_read(sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free(bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;

  off_t ending_size = size + offset;
  struct inode_disk* disk_inode = malloc(sizeof(struct inode_disk));
  cache_read(inode->sector, disk_inode);

  bool success = true;
  if (ending_size > disk_inode->length) {
    success &= inode_resize(disk_inode, ending_size);
    if (success) {
      disk_inode->length = ending_size;
    }
  }

  cache_write(inode->sector, disk_inode);
  free(disk_inode);
  if (!success) {
    return 0;
  }

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      cache_write(sector_idx, buffer + bytes_written);
    } else {
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }

      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        cache_read(sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      cache_write(sector_idx, bounce);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  free(bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) {
  struct inode_disk* disk_inode = malloc(BLOCK_SECTOR_SIZE);
  cache_read(inode->sector, disk_inode);
  off_t to_ret = disk_inode->length;
  free(disk_inode);
  return to_ret;
}

bool is_removed(const struct inode* inode) { return inode->removed; }