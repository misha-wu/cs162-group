#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "filesys/buffer.h"


/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define NUM_DIRECT 10

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  block_sector_t direct[NUM_DIRECT]; // direct pointers
  block_sector_t indirect; // indirect pointers
  block_sector_t dbl_indirect; // doubly indirect pointer
  bool is_dir;
  off_t length;         /* File size in bytes. */
  unsigned magic;       /* Magic number. */
  uint32_t unused[113]; /* Not used. */
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct lock lock; // copium for real my dudes :(
};

struct lock* get_inode_lock(struct inode* inode) {
  return &inode->lock;
}

int get_open_count(struct inode* inode) {
  return inode->open_cnt;
}

struct inode_disk* get_id(struct inode* inode) {
  return (struct inode_disk*) cache_read_ret(fs_device, inode->sector);
}

bool get_is_dir(struct inode* inode) {
  struct inode_disk* id = get_id(inode);
  bool is_dir = id->is_dir;
  return is_dir;
}

block_sector_t get_sector(struct inode* inode) {
  
  return inode->sector;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  block_sector_t ret;

  struct inode_disk* disk_inode = (struct inode_disk*) cache_read_ret(fs_device, inode->sector);
  if (pos < NUM_DIRECT * BLOCK_SECTOR_SIZE) {
    ret = disk_inode->direct[pos / BLOCK_SECTOR_SIZE];
    return ret;
  } else if (pos < NUM_DIRECT * BLOCK_SECTOR_SIZE + 128 * BLOCK_SECTOR_SIZE) {
    block_sector_t* buffer = (block_sector_t*) cache_read_ret(fs_device, disk_inode->indirect);
    off_t relative_pos = pos - NUM_DIRECT * BLOCK_SECTOR_SIZE;
    ret = buffer[relative_pos / BLOCK_SECTOR_SIZE];
    return ret;
  } else {
    int num_pointers = BLOCK_SECTOR_SIZE / sizeof(block_sector_t);

    block_sector_t* buffer = (block_sector_t*) cache_read_ret(fs_device, disk_inode->dbl_indirect);
    off_t relative_pos = pos - NUM_DIRECT * BLOCK_SECTOR_SIZE - 128 * BLOCK_SECTOR_SIZE;
    off_t index_in_doubly = relative_pos / (num_pointers * BLOCK_SECTOR_SIZE);
    buffer = (block_sector_t*) cache_read_ret(fs_device, buffer[index_in_doubly]);
    off_t rel_rel_pos = pos - NUM_DIRECT * BLOCK_SECTOR_SIZE - 128 * BLOCK_SECTOR_SIZE - index_in_doubly * num_pointers * BLOCK_SECTOR_SIZE;
    ret = buffer[rel_rel_pos / BLOCK_SECTOR_SIZE];
    return ret;
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
struct lock open_inodes_lock;

/* Initializes the inode module. */
void inode_init(void) { 
  list_init(&open_inodes); 
  lock_init(&open_inodes_lock);
}

bool inode_resize(struct inode_disk* id, off_t size) {
  for (int i = 0; i < NUM_DIRECT; i++) {
    if (size <= BLOCK_SECTOR_SIZE * i && id->direct[i] != 0) {
      free_map_release(id->direct[i], 1);
      id->direct[i] = 0;
    } else if (size > BLOCK_SECTOR_SIZE * i && id->direct[i] == 0) {
      if (!free_map_allocate(1, &id->direct[i])) {
        inode_resize(id, 0);
        return false;
      }
    }
  }
  
  if (id->indirect == 0 && size <= NUM_DIRECT * BLOCK_SECTOR_SIZE) {
    return true;
  }
  
  block_sector_t* buffer;
  bool free_buffer = false;
  
  if (id->indirect == 0) {
    if (!free_map_allocate(1, &id->indirect)) {
      inode_resize(id, 0);
      return false;
    }
    buffer = calloc(1, BLOCK_SECTOR_SIZE);
    free_buffer = true;
  } else {
    buffer = cache_read_ret(fs_device, id->indirect);
  }

  for (int i = 0; i < 128; i++) {
    if (size <= (NUM_DIRECT + i) * BLOCK_SECTOR_SIZE && buffer[i] != 0) {
      free_map_release(buffer[i], 1);
      buffer[i] = 0;
    } else if (size > (NUM_DIRECT + i) * BLOCK_SECTOR_SIZE && buffer[i] == 0) {
      if (!free_map_allocate(1, &buffer[i])) {
        inode_resize(id, 0);
        return false;
      }
    }
  }

  if (size <= NUM_DIRECT * BLOCK_SECTOR_SIZE) {
    free_map_release(id->indirect, 1);
    id->indirect = 0;
  } else {
    cache_write(fs_device, id->indirect, buffer);
  }

  if (free_buffer) {
    free(buffer);
  }
  
  if (id->dbl_indirect == 0 && size <= (NUM_DIRECT + 128) * BLOCK_SECTOR_SIZE) {
    return true;
  }
  
  block_sector_t* dbl_buffer;
  bool free_dbl_buffer = false;
  if (id->dbl_indirect == 0) {
    if (!free_map_allocate(1, &id->dbl_indirect)) {
      inode_resize(id, 0);
      return false;
    }
    dbl_buffer = calloc(1, BLOCK_SECTOR_SIZE);
    free_dbl_buffer = true;
  } else {
    dbl_buffer = cache_read_ret(fs_device, id->dbl_indirect);
  }

  for (int i = 0; i < 128; i++) {
    if (size <= (NUM_DIRECT + 128 + (i + 1) * 128) * BLOCK_SECTOR_SIZE && dbl_buffer[i] != 0) {
      block_sector_t* sgl_buffer = cache_read_ret(fs_device, dbl_buffer[i]);
      for (int j = 0; j < 128; j++) {
        if (size <= (NUM_DIRECT + 128 + i * 128 + j) * BLOCK_SECTOR_SIZE && sgl_buffer[j] != 0) {
          free_map_release(sgl_buffer[j], 1);
          sgl_buffer[j] = 0;
        }
      }
      if (size <= (NUM_DIRECT + 128 + i * 128)) { // did not need block at all
        free_map_release(dbl_buffer[i], 1);
        dbl_buffer[i] = 0;
      } else {
        cache_write(fs_device, dbl_buffer[i], sgl_buffer);
      }
    }
    
    if (size > (NUM_DIRECT + 128 + i * 128) * BLOCK_SECTOR_SIZE) {
      // grow
      block_sector_t* sgl_buffer;
      bool free_sgl_buffer = false;
      if (dbl_buffer[i] == 0) {
        if (!free_map_allocate(1, &dbl_buffer[i])) {
          inode_resize(id, 0);
          return false;
        }
        sgl_buffer = calloc(1, BLOCK_SECTOR_SIZE);
        free_sgl_buffer = true;
      } else {
        sgl_buffer = cache_read_ret(fs_device, dbl_buffer[i]);
      }
      
      for (int j = 0; j < 128; j++) {
        if (size > (NUM_DIRECT + 128 + i * 128 + j) * BLOCK_SECTOR_SIZE && sgl_buffer[j] == 0) {
          if (!free_map_allocate(1, &sgl_buffer[j])) {
            inode_resize(id, 0);
            return false;
          }
        }
      }

      cache_write(fs_device, dbl_buffer[i], sgl_buffer);
      if (free_sgl_buffer) {
        free(sgl_buffer);
      }
    }
  }
  
  if (size <= (NUM_DIRECT + 128) * BLOCK_SECTOR_SIZE) {
    free_map_release(id->dbl_indirect, 1);
    id->dbl_indirect = 0;
  } else {
    cache_write(fs_device, id->dbl_indirect, dbl_buffer);
  }

  if (free_dbl_buffer) {
    free(dbl_buffer);
  }

  return true;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  disk_inode = calloc(1, sizeof *disk_inode);

  if (disk_inode != NULL) {
    bool resize_success = inode_resize(disk_inode, length);

    if (resize_success) {
      disk_inode->length = length;
      success = true;
    }
    disk_inode->is_dir = false;
    cache_write(fs_device, sector, disk_inode);
    free(disk_inode);
  }
  return success;
}

bool inode_create_dir(block_sector_t sector, off_t length) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);

  if (disk_inode != NULL) {
    bool resize_success = inode_resize(disk_inode, length);

    if (resize_success) {
      disk_inode->length = length;

      success = true;
    }
    disk_inode->is_dir = true;
    cache_write(fs_device, sector, disk_inode);
    free(disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  lock_acquire(&open_inodes_lock);
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      lock_release(&open_inodes_lock);
      return inode;
    }
  }
  lock_release(&open_inodes_lock);

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  lock_acquire(&open_inodes_lock);
  list_push_front(&open_inodes, &inode->elem);
  lock_release(&open_inodes_lock);
  lock_init(&inode->lock);
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

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      cache_block_t* cache_entry = cache_read(fs_device, inode->sector);
      struct inode_disk* id = (struct inode_disk*) cache_entry->contents;
      lock_acquire(&cache_entry->lock);
      inode_resize(id, 0);
      id->length = 0;
      lock_release(&cache_entry->lock);
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

off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0) {
    lock_acquire(&inode->lock);
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    lock_release(&inode->lock);
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0) {
      break;
    }

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      cache_block_t* cache_entry = cache_read(fs_device, sector_idx);
      memcpy(buffer + bytes_read, cache_entry->contents, BLOCK_SECTOR_SIZE);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      cache_block_t* cache_entry = cache_read(fs_device, sector_idx);
      memcpy(buffer + bytes_read, cache_entry->contents + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }  
  return bytes_read;
}

off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;

  lock_acquire(&inode->lock);
  if (inode->deny_write_cnt) {
    lock_release(&inode->lock);
    return 0;
  }


  off_t inode_len = inode_length(inode);
  lock_release(&inode->lock);

  lock_acquire(&inode->lock);
  struct inode_disk* id;
  if (size + offset >= inode_len) {  
    cache_block_t* cache_entry = cache_read(fs_device, inode->sector);
    id = (struct inode_disk*) cache_entry->contents;
    lock_acquire(&cache_entry->lock);
    inode_resize(id, size + offset);
    inode_len = size + offset;
    id->length = size + offset;
    lock_release(&cache_entry->lock);
    cache_write(fs_device, inode->sector, id);
  }

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_len - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0) {
      break;
    }

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      cache_write(fs_device, sector_idx, buffer + bytes_written);
    } else {

      cache_block_t* cache_entry;
      uint8_t* fake_bounce = NULL;
      
      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left) {
        cache_entry = cache_read(fs_device, sector_idx);
      } else {
        memset(cache_entry->contents, 0, BLOCK_SECTOR_SIZE);
      }
      memcpy(cache_entry->contents + sector_ofs, buffer + bytes_written, chunk_size);
      cache_write(fs_device, sector_idx, cache_entry->contents);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
    
  }
  lock_release(&inode->lock);
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
  struct inode_disk* id = calloc(1, sizeof(struct inode_disk));
  if (id == NULL) {
    return -1; // ???
  }
  cache_read_buffer(fs_device, inode->sector, id);
  int length = id->length;
  free(id);
  return length;
}
