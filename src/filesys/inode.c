#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
// #include "filesys/directory.h"
#include "filesys/buffer.h"


/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  // block_sector_t start; /* First data sector. */
  block_sector_t direct[10]; // direct pointers
  block_sector_t indirect; // indirect pointers
  block_sector_t dbl_indirect; // doubly indirect pointer
  struct lock lock;
  bool is_dir;
  off_t length;         /* File size in bytes. */
  unsigned magic;       /* Magic number. */
  uint32_t unused[107]; /* Not used. */
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
  struct inode_disk data; /* Inode content. */
};



void cache_init() {
  // start: wo de buffer cache code 
  lock_init(&global_cache_lock);
  // free_map = malloc(64 * sizeof(bool));
  for (int i = 0; i < 64; i++) {
    free_map[i] = true;
    cache[i] = NULL;
  }
  clock_index = 0;
    // end: wo de buffer cache code

}

void cache_flush() {
  for (int i = 0; i < 64; i++) {
    if (cache[i] == NULL) {
      continue;
    }
    if (cache[i]->dirty) {
      block_write(cache[i]->block, cache[i]->sector, cache[i]->contents);
    }
    free(cache[i]);
  }
}

int get_open_count(struct inode* inode) {
  return inode->open_cnt;
}

struct inode_disk* get_id(struct inode* inode) {
  struct inode_disk* id = calloc(1, sizeof(struct inode_disk));
  if (id == NULL) {
    return false; // ???
  }
  cache_read_buffer(fs_device, inode->sector, id);
  return id;
}

bool get_is_dir(struct inode* inode) {
  struct inode_disk* id = get_id(inode);
  bool is_dir = id->is_dir;
  free(id);
  return is_dir;
}

block_sector_t get_sector(struct inode* inode) {
  
  return inode->sector;
}

// /* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
//    next call will return the next file name part. Returns 1 if successful, 0 at
//    end of string, -1 for a too-long file name part. */
// static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
//   const char* src = *srcp;
//   char* dst = part;

//   /* Skip leading slashes.  If it's all slashes, we're done. */
//   while (*src == '/')
//     src++;
//   if (*src == '\0')
//     return 0;

//   /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
//   while (*src != '/' && *src != '\0') {
//     if (dst < part + NAME_MAX)
//       *dst++ = *src;
//     else
//       return -1;
//     src++;
//   }
//   *dst = '\0';

//   /* Advance source pointer. */
//   *srcp = src;
//   return 1;
// }

// static int get_last_part(char part[NAME_MAX + 1], const char** srcp) {
//   while (status = get_next_part(part, srcp) == 1);
//   return status;
// }

// struct inode* path_resolution(const char* filename, bool last_should_exist) {
//   struct dir* curr_dir;
//   if (filename[0] != '/') {
//     curr_dir = dir_open_root();
//   } else {
//     curr_dir = dir_reopen(process_current()->cwd);
//   }
//   if (curr_dir == NULL) {
//     return NULL;
//   }
//   char part[NAME_MAX + 1];
//   bool was_file;
//   int status = get_next_part(part, &filename);
//   while (true) {
    
//     if (status == 0) {
//       break;
//     }
//     if (status == -1) {
//       return NULL;
//     }
//     struct inode* inode;
//     status = get_next_part(part, &filename);
//     bool found = dir_lookup(curr_dir, part, &inode);
//     if (!found) {
//       if (status == 0 && !last_should_exist) {
//         struct inode* help = curr_dir->inode;
//         close(curr_dir);
//         return help;
//       }
//       return NULL;
//     }
    
//     bool is_dir = get_id(inode)->is_dir;
//     dir_close(curr_dir);
//     if (status == 0) {
//       return inode;
//     }
//     if (is_dir) {
//       curr_dir = dir_open(inode);
//     }
//   }
//   dir_close(curr_dir);
//   return NULL;

// }

// char* get_full_path(dir* dir) {
//   // if dir is the root:
//     // return ''
  
//   if (dir->inode->sector == ROOT_DIR_SECTOR) {
//     return strdup("/");
//   }
//   char* path = get_full_path(dir->parent);
//   char* fullpath = malloc(strlen(path) + strlen(name) + 2);
//   snprintf(fullpath, "%s/%s", path, name);
//   return fullpath;
//   // return strdup(get_full_path(dir->parent) + "/" + name);
// }


// struct inode* path_resolution(const char* filename) {
//   struct dir* curr_dir;
//   if (filename[0] != '/') {
//     curr_dir = 
//   }
//   char* full_path = filename;
//   // if filename begins with "./":
//   //   full_path = get_full_path(cwd) + filename[2:]
//   // else if filename begins with "../":
//   //   full_path = get_full_path(cwd->parent) + filename[3:]
//   // else if filename does not begin with "/": // this is not an absolute path
//   //   full_path = get_full_path(cwd) + filename
//   if (filename[0] != '/') {
//     full_path = 
//   }
  
//   struct dir* dir = dir_open_root()
//   struct inode* inode = NULL
//   if (dir == NULL) return NULL
//   char part[NAME_MAX + 1]
//   get_next_part(part, &full_path)
//   while true:
//     if (!dir_lookup(dir, part, &inode)):
//       return NULL
//     dir_close(dir)
//     success = get_next_part(part, &full_path)
//     if success == 0: //at the end of path
//       break
//     dir = dir_open(inode)
//   return inode
// }

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  struct inode_disk* disk_inode = calloc(1, sizeof(struct inode_disk));
  if (disk_inode == NULL) {
    return -1;
  }

  block_sector_t ret;
  cache_read_buffer(fs_device, inode->sector, disk_inode);
  if (pos < 10 * BLOCK_SECTOR_SIZE) {
    ret = disk_inode->direct[pos / BLOCK_SECTOR_SIZE];
    free(disk_inode);
    return ret;
  } else if (pos < 10 * BLOCK_SECTOR_SIZE + 128 * BLOCK_SECTOR_SIZE) {
    block_sector_t buffer[128];
    cache_read_buffer(fs_device, disk_inode->indirect, buffer);
    off_t relative_pos = pos - 10 * BLOCK_SECTOR_SIZE;
    ret = buffer[relative_pos / BLOCK_SECTOR_SIZE];
    free(disk_inode);
    return ret;
  } else {

    // uhhh this math is kinda sus

    int num_pointers = BLOCK_SECTOR_SIZE / sizeof(block_sector_t);

    block_sector_t buffer[128];
    cache_read_buffer(fs_device, disk_inode->dbl_indirect, buffer);
    off_t relative_pos = pos - 10 * BLOCK_SECTOR_SIZE - 128 * BLOCK_SECTOR_SIZE;
    off_t index_in_doubly = relative_pos / (num_pointers * BLOCK_SECTOR_SIZE);
    cache_read_buffer(fs_device, buffer[index_in_doubly], buffer);
    off_t rel_rel_pos = pos - 10 * BLOCK_SECTOR_SIZE - 128 * BLOCK_SECTOR_SIZE - index_in_doubly * num_pointers * BLOCK_SECTOR_SIZE;
    ret = buffer[rel_rel_pos / BLOCK_SECTOR_SIZE];
    free(disk_inode);
    return ret;
  }


  // ASSERT(inode != NULL);
  // if (pos < inode->data.length)
  //   return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  // else
  //   return -1;

  // ASSERT(inode != NULL);
  // if (pos < disk_inode->length)
  //   return disk_inode->direct[0] + pos / BLOCK_SECTOR_SIZE;
  // else
  //   return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) { list_init(&open_inodes); }


bool inode_resize(struct inode_disk* id, off_t size) {
  for (int i = 0; i < 10; i++) {
    if (size <= BLOCK_SECTOR_SIZE * i && id->direct[i] != 0) {
      free_map_release(id->direct[i], 1);
      id->direct[i] = 0;
    } else if (size > BLOCK_SECTOR_SIZE * i && id->direct[i] == 0) {
      if (!free_map_allocate(1, &id->direct[i])) {
        inode_resize(id, 0);
      }
    }
  }

  // printf("did directs\n");
  
  if (id->indirect == 0 && size <= 10 * BLOCK_SECTOR_SIZE) {
    // id->length = size;
    return true;
  }
  
  block_sector_t buffer[128];
  memset(buffer, 0, 512);
  if (id->indirect == 0) {
    if (!free_map_allocate(1, &id->indirect)) {
      inode_resize(id, 0);
    }
  } else {
    cache_read_buffer(fs_device, id->indirect, buffer);
  }

  // printf("created/read an indirect\n");

  for (int i = 0; i < 128; i++) {
    if (size <= (10 + i) * BLOCK_SECTOR_SIZE && buffer[i] != 0) {
      free_map_release(buffer[i], 1);
      buffer[i] = 0;
    } else if (size > (10 + i) * BLOCK_SECTOR_SIZE && buffer[i] == 0) {
      if (!free_map_allocate(1, &buffer[i])) {
        inode_resize(id, 0);
      }
    }
  }

  if (size <= 10 * BLOCK_SECTOR_SIZE) {
    free_map_release(id->indirect, 1);
    id->indirect = 0;
  } else {
    cache_write(fs_device, id->indirect, buffer);
  }

  // printf("dealt with indirects\n");
  
  if (id->dbl_indirect == 0 && size <= (10 + 128) * BLOCK_SECTOR_SIZE) {
    // id->length = size;
    return true;
  }
  
  block_sector_t dbl_buffer[128];
  memset(dbl_buffer, 0, 512);
  if (id->dbl_indirect == 0) {
    if (!free_map_allocate(1, &id->dbl_indirect)) {
      inode_resize(id, 0);
    }
  } else {
    cache_read_buffer(fs_device, id->dbl_indirect, dbl_buffer);
  }
  for (int i = 0; i < 128; i++) {
    // fix the shrink
    // if (size <= (10 + 128 + (i + 1) * 128) * BLOCK_SECTOR_SIZE && dbl_buffer[i] != 0) {
    //   // shrink (do not need the whole double block)
    //   block_sector_t sgl_buffer[128];
    //   memset(sgl_buffer, 0, 512);
    //   block_read(fs_device, dbl_buffer[i], sgl_buffer);
    //   for (int j = 0; j < 128; j++) {
    //     if (size <= (10 + 128 + i * 128 * 128 + j * 128) * BLOCK_SECTOR_SIZE && sgl_buffer[j] != 0) {
    //       free_map_release(sgl_buffer[j], 1);
    //       sgl_buffer[j] = 0;
    //     }
    //   }
    //   if (size <= (10 + 128 + i * 128 * 128)) { // did not need block at all
    //     free_map_release(dbl_buffer[i], 1);
    //     dbl_buffer[i] = 0;
    //   } else {
    //     block_write(fs_device, dbl_buffer[i], sgl_buffer);
    //   }
    // // } else if (size > (10 + 128 + i * 128 * 128) * BLOCK_SECTOR_SIZE) {
    // } else 
    if (size <= (10 + 128 + (i + 1) * 128) * BLOCK_SECTOR_SIZE && dbl_buffer[i] != 0) {
      // shrink (do not need the whole double block)
       block_sector_t sgl_buffer[128];
      memset(sgl_buffer, 0, 512);
      cache_read_buffer(fs_device, dbl_buffer[i], sgl_buffer);
      for (int j = 0; j < 128; j++) {
        if (size <= (10 + 128 + i * 128 + j) * BLOCK_SECTOR_SIZE && sgl_buffer[j] != 0) {
          free_map_release(sgl_buffer[j], 1);
          sgl_buffer[j] = 0;
        }
      }
      if (size <= (10 + 128 + i * 128)) { // did not need block at all
        free_map_release(dbl_buffer[i], 1);
        dbl_buffer[i] = 0;
      } else {
        cache_write(fs_device, dbl_buffer[i], sgl_buffer);
      }
    }
    
    if (size > (10 + 128 + i * 128) * BLOCK_SECTOR_SIZE) {
      // grow, kinda sus check
      block_sector_t sgl_buffer[128];
      memset(sgl_buffer, 0, 512);
      if (dbl_buffer[i] == 0) {
        if (!free_map_allocate(1, &dbl_buffer[i])) {
          inode_resize(id, 0);
        }
      } else {
        cache_read_buffer(fs_device, dbl_buffer[i], sgl_buffer);
      }

      // seems okay on initial check???
      for (int j = 0; j < 128; j++) {
        if (size > (10 + 128 + i * 128 + j) * BLOCK_SECTOR_SIZE && sgl_buffer[j] == 0) {
          // printf("allocated double pointer i: %d, and single pointer j: %d\n", i, j);
        // if (size > (10 + 128 + i * 128 * 128 + j * 128) * BLOCK_SECTOR_SIZE && sgl_buffer[j] == 0) {
          if (!free_map_allocate(1, &sgl_buffer[j])) {
            inode_resize(id, 0);
          }
        }
      }

      cache_write(fs_device, dbl_buffer[i], sgl_buffer);
    }
  }
  
  if (size <= (10 + 128) * BLOCK_SECTOR_SIZE) {
    free_map_release(id->dbl_indirect, 1);
    id->dbl_indirect = 0;
  } else {
    cache_write(fs_device, id->dbl_indirect, dbl_buffer);
  }

  // id->length = size;
  return true;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  // printf("creating inode with length %d\n", length);
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  //    printf("lock size %d\n", sizeof(struct lock));
  // printf("\ndisk inode size %d\n", sizeof *disk_inode);
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    // size_t sectors = bytes_to_sectors(length);
    // disk_inode->length = length;
    // disk_inode->magic = INODE_MAGIC;
    // if (free_map_allocate(sectors, &disk_inode->start)) {
    //   block_write(fs_device, sector, disk_inode);
    //   if (sectors > 0) {
    //     static char zeros[BLOCK_SECTOR_SIZE];
    //     size_t i;

    //     for (i = 0; i < sectors; i++)
    //       block_write(fs_device, disk_inode->start + i, zeros);
    //   }
    //   success = true;
    // }
    // size_t sectors = bytes_to_sectors(length);
    // disk_inode->length = length;
    // disk_inode->magic = INODE_MAGIC;
    // if (free_map_allocate(sectors, &disk_inode->direct[0])) {
    //   block_write(fs_device, sector, disk_inode);
    //   if (sectors > 0) {
    //     static char zeros[BLOCK_SECTOR_SIZE];
    //     size_t i;

    //     for (i = 0; i < sectors; i++)
    //       block_write(fs_device, disk_inode->direct[0] + i, zeros);
    //   }
    //   success = true;
    // }
    struct inode_disk* id = calloc(1, sizeof(struct inode_disk));
    if (id == NULL) {
      return false;
    }
    if (inode_resize(disk_inode, length)) {
      disk_inode->length = length;
      success = true;
    }
    disk_inode->is_dir = false;
    cache_write(fs_device, sector, disk_inode);
    free(id);
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
  //    printf("lock size %d\n", sizeof(struct lock));
  // printf("\ndisk inode size %d\n", sizeof *disk_inode);
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    struct inode_disk* id = calloc(1, sizeof(struct inode_disk));
    if (id == NULL) {
      return false;
    }
    if (inode_resize(disk_inode, length)) {
      disk_inode->length = length;
      success = true;
    }
    disk_inode->is_dir = true;
    cache_write(fs_device, sector, disk_inode);
    free(id);
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
  // block_read(fs_device, inode->sector, &inode->data);
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
      struct inode_disk* id = calloc(1, sizeof(struct inode_disk));
      if (id == NULL) {
        return false; // ???
      }
      cache_read_buffer(fs_device, inode->sector, id);
      inode_resize(id, 0);
      id->length = 0;
      free(id);
      // free_map_release(inode->sector, 1);
      // free_map_release(inode->data.start, bytes_to_sectors(inode->data.length));
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
// off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
//   uint8_t* buffer = buffer_;
//   off_t bytes_read = 0;
//   uint8_t* bounce = NULL;

//   while (size > 0) {
//     /* Disk sector to read, starting byte offset within sector. */
//     block_sector_t sector_idx = byte_to_sector(inode, offset);
//     int sector_ofs = offset % BLOCK_SECTOR_SIZE;

//     /* Bytes left in inode, bytes left in sector, lesser of the two. */
//     off_t inode_left = inode_length(inode) - offset;
//     int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
//     int min_left = inode_left < sector_left ? inode_left : sector_left;

//     // printf("offset %d is at sector %d, has inode left %d, sector left %d\n", offset, sector_idx, inode_left, sector_left);

//     /* Number of bytes to actually copy out of this sector. */
//     int chunk_size = size < min_left ? size : min_left;
//     if (chunk_size <= 0)
//       break;

//     if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
//       /* Read full sector directly into caller's buffer. */
//       block_read(fs_device, sector_idx, buffer + bytes_read);
//     } else {
//       /* Read sector into bounce buffer, then partially copy
//              into caller's buffer. */
//       if (bounce == NULL) {
//         bounce = malloc(BLOCK_SECTOR_SIZE);
//         if (bounce == NULL)
//           break;
//       }
//       block_read(fs_device, sector_idx, bounce);
//       memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
//     }

//     /* Advance. */
//     size -= chunk_size;
//     offset += chunk_size;
//     bytes_read += chunk_size;
//   }
//   free(bounce);

//   return bytes_read;
// }

//funsies
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
  // uint8_t* bounce = NULL;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    // printf("offset %d is at sector %d, has inode left %d, sector left %d\n", offset, sector_idx, inode_left, sector_left);

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
//       block_read(fs_device, sector_idx, buffer + bytes_read);
      cache_block_t* cache_entry = cache_read(fs_device, sector_idx);
      memcpy(buffer + bytes_read, cache_entry->contents, BLOCK_SECTOR_SIZE);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      // if (bounce == NULL) {
      //   bounce = malloc(BLOCK_SECTOR_SIZE);
      //   if (bounce == NULL)
      //     break;
      // }
      // block_read(fs_device, sector_idx, bounce);
      cache_block_t* cache_entry = cache_read(fs_device, sector_idx);
      // memcpy(bounce, cache_entry->contents, BLOCK_SECTOR_SIZE);
      memcpy(buffer + bytes_read, cache_entry->contents + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  // free(bounce);

  return bytes_read;
}

// modified to use buffer cache
// off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
//   uint8_t* buffer = buffer_;
//   off_t bytes_read = 0;

//   while (size > 0) {
//     /* Disk sector to read, starting byte offset within sector. */
//     block_sector_t sector_idx = byte_to_sector(inode, offset);
//     int sector_ofs = offset % BLOCK_SECTOR_SIZE;

//     /* Bytes left in inode, bytes left in sector, lesser of the two. */
//     off_t inode_left = inode_length(inode) - offset;
//     int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
//     int min_left = inode_left < sector_left ? inode_left : sector_left;

//     // printf("offset %d is at sector %d, has inode left %d, sector left %d\n", offset, sector_idx, inode_left, sector_left);

//     /* Number of bytes to actually copy out of this sector. */
//     int chunk_size = size < min_left ? size : min_left;
//     if (chunk_size <= 0)
//       break;

//     cache_block_t* cache_block = cache_read(fs_device, sector_idx, buffer + bytes_read);

//     /* Advance. */
//     size -= chunk_size;
//     offset += chunk_size;
//     bytes_read += chunk_size;
//   }
//   // free(bounce);

//   return bytes_read;
// }

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
// off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
//   const uint8_t* buffer = buffer_;
//   off_t bytes_written = 0;
//   uint8_t* bounce = NULL;

//   if (inode->deny_write_cnt)
//     return 0;


//   off_t inode_len = inode_length(inode);

//   struct inode_disk* id = calloc(1, sizeof(struct inode_disk));
//   if (id == NULL) {
//     return 0;
//   }

//   if (size + offset >= inode_len) {  
//     block_read(fs_device, inode->sector, id);
//     inode_resize(id, size + offset);
//     inode_len = size + offset;
//     id->length = size + offset;
//     block_write(fs_device, inode->sector, id);
//   }

//   while (size > 0) {
//     /* Sector to write, starting byte offset within sector. */
//     block_sector_t sector_idx = byte_to_sector(inode, offset);
//     int sector_ofs = offset % BLOCK_SECTOR_SIZE;

//     /* Bytes left in inode, bytes left in sector, lesser of the two. */
//     off_t inode_left = inode_len - offset;
//     // off_t inode_left = inode_length(inode) - offset;
//     int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
//     int min_left = inode_left < sector_left ? inode_left : sector_left;

//     /* Number of bytes to actually write into this sector. */
//     int chunk_size = size < min_left ? size : min_left;
//     if (chunk_size <= 0)
//       break;

//     if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
//       /* Write full sector directly to disk. */
//       block_write(fs_device, sector_idx, buffer + bytes_written);
//     } else {
//       /* We need a bounce buffer. */
//       if (bounce == NULL) {
//         bounce = malloc(BLOCK_SECTOR_SIZE);
//         if (bounce == NULL)
//           break;
//       }

//       /* If the sector contains data before or after the chunk
//              we're writing, then we need to read in the sector
//              first.  Otherwise we start with a sector of all zeros. */
//       if (sector_ofs > 0 || chunk_size < sector_left)
//         block_read(fs_device, sector_idx, bounce);
//       else
//         memset(bounce, 0, BLOCK_SECTOR_SIZE);
//       memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
//       block_write(fs_device, sector_idx, bounce);
//     }

//     /* Advance. */
//     size -= chunk_size;
//     offset += chunk_size;
//     bytes_written += chunk_size;
//   }
//   free(bounce);

//   if (size + offset > inode_len) {
//     block_write(fs_device, inode->sector, id);
//   }

//   free(id);

//   return bytes_written;
// }

// modified to use cache
// off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
//   const uint8_t* buffer = buffer_;
//   off_t bytes_written = 0;
//   // uint8_t* bounce = NULL;

//   if (inode->deny_write_cnt)
//     return 0;


//   off_t inode_len = inode_length(inode);

//   struct inode_disk* id = calloc(1, sizeof(struct inode_disk));
//   if (id == NULL) {
//     return 0;
//   }

//   if (size + offset >= inode_len) {  
//     cache_read(fs_device, inode->sector, id);
//     inode_resize(id, size + offset);
//     inode_len = size + offset;
//     id->length = size + offset;
//     cache_write(fs_device, inode->sector, id);
//   }

//   while (size > 0) {
//     /* Sector to write, starting byte offset within sector. */
//     block_sector_t sector_idx = byte_to_sector(inode, offset);
//     int sector_ofs = offset % BLOCK_SECTOR_SIZE;

//     /* Bytes left in inode, bytes left in sector, lesser of the two. */
//     off_t inode_left = inode_len - offset;
//     // off_t inode_left = inode_length(inode) - offset;
//     int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
//     int min_left = inode_left < sector_left ? inode_left : sector_left;

//     /* Number of bytes to actually write into this sector. */
//     int chunk_size = size < min_left ? size : min_left;
//     if (chunk_size <= 0)
//       break;

//     // if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
//     //   /* Write full sector directly to disk. */
//     //   block_write(fs_device, sector_idx, buffer + bytes_written);
//     // } else {
//     //   /* We need a bounce buffer. */
//     //   if (bounce == NULL) {
//     //     bounce = malloc(BLOCK_SECTOR_SIZE);
//     //     if (bounce == NULL)
//     //       break;
//     //   }

//     //   /* If the sector contains data before or after the chunk
//     //          we're writing, then we need to read in the sector
//     //          first.  Otherwise we start with a sector of all zeros. */
//     //   if (sector_ofs > 0 || chunk_size < sector_left)
//     //     block_read(fs_device, sector_idx, bounce);
//     //   else
//     //     memset(bounce, 0, BLOCK_SECTOR_SIZE);
//     //   memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
//     //   block_write(fs_device, sector_idx, bounce);
//     // }
//     cache_write(fs_device, sector_idx, buffer + bytes_written);

//     /* Advance. */
//     size -= chunk_size;
//     offset += chunk_size;
//     bytes_written += chunk_size;
//   }
//   // free(bounce);

//   if (size + offset > inode_len) {
//     cache_write(fs_device, inode->sector, id);
//   }

//   free(id);

//   return bytes_written;
// }

// funsies
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;


  off_t inode_len = inode_length(inode);

  struct inode_disk* id = calloc(1, sizeof(struct inode_disk));
  if (id == NULL) {
    return 0;
  }

  if (size + offset >= inode_len) {  
    cache_read_buffer(fs_device, inode->sector, id);
    inode_resize(id, size + offset);
    inode_len = size + offset;
    id->length = size + offset;
    cache_write(fs_device, inode->sector, id);
  }

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_len - offset;
    // off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      // block_write(fs_device, sector_idx, buffer + bytes_written);
      cache_write(fs_device, sector_idx, buffer + bytes_written);
    } else {
      /* We need a bounce buffer. */
      // if (bounce == NULL) {
      //   bounce = malloc(BLOCK_SECTOR_SIZE);
      //   if (bounce == NULL)
      //     break;
      // }

      // cache_block_t* cache_entry;
      // uint8_t* fake_bounce = NULL;
      
      // /* If the sector contains data before or after the chunk
      //        we're writing, then we need to read in the sector
      //        first.  Otherwise we start with a sector of all zeros. */
      // if (sector_ofs > 0 || chunk_size < sector_left) {
      //   // block_read(fs_device, sector_idx, bounce);
      //   cache_entry = cache_read(fs_device, sector_idx);
      //   fake_bounce = cache_entry->contents;
      //   // memcpy(bounce, cache_entry->contents, BLOCK_SECTOR_SIZE);
      // } else {
      //   // memset(bounce, 0, BLOCK_SECTOR_SIZE);
      //   memset(fake_bounce, 0, BLOCK_SECTOR_SIZE);
      // }
      // // memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      // // // block_write(fs_device, sector_idx, bounce);
      // // cache_write(fs_device, sector_idx, bounce);
      // memcpy(fake_bounce + sector_ofs, buffer + bytes_written, chunk_size);
      // // block_write(fs_device, sector_idx, bounce);
      // cache_write(fs_device, sector_idx, fake_bounce);

      cache_block_t* cache_entry;
      uint8_t* fake_bounce = NULL;
      
      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left) {
        // block_read(fs_device, sector_idx, bounce);
        cache_entry = cache_read(fs_device, sector_idx);
        // fake_bounce = cache_entry->contents;
        // memcpy(bounce, cache_entry->contents, BLOCK_SECTOR_SIZE);
      } else {
        // memset(bounce, 0, BLOCK_SECTOR_SIZE);
        memset(cache_entry->contents, 0, BLOCK_SECTOR_SIZE);
      }
      // memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      // // block_write(fs_device, sector_idx, bounce);
      // cache_write(fs_device, sector_idx, bounce);
      memcpy(cache_entry->contents + sector_ofs, buffer + bytes_written, chunk_size);
      // block_write(fs_device, sector_idx, bounce);
      cache_write(fs_device, sector_idx, cache_entry->contents);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  free(bounce);

  if (size + offset > inode_len) {
    // block_write(fs_device, inode->sector, id);
    cache_write(fs_device, inode->sector, id);
  }

  free(id);

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
  // return inode->data.length; 
  struct inode_disk* id = calloc(1, sizeof(struct inode_disk));
  if (id == NULL) {
    return -1; // ???
  }
  cache_read_buffer(fs_device, inode->sector, id);
  int length = id->length;
  free(id);
  return length;
}


// #include "filesys/inode.h"
// #include <list.h>
// #include <debug.h>
// #include <round.h>
// #include <string.h>
// #include "filesys/filesys.h"
// #include "filesys/free-map.h"
// #include "threads/malloc.h"

// /* Identifies an inode. */
// #define INODE_MAGIC 0x494e4f44

// /* On-disk inode.
//    Must be exactly BLOCK_SECTOR_SIZE bytes long. */
// struct inode_disk {
//   block_sector_t start; /* First data sector. */
//   off_t length;         /* File size in bytes. */
//   unsigned magic;       /* Magic number. */
//   uint32_t unused[125]; /* Not used. */
// };

// /* Returns the number of sectors to allocate for an inode SIZE
//    bytes long. */
// static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

// /* In-memory inode. */
// struct inode {
//   struct list_elem elem;  /* Element in inode list. */
//   block_sector_t sector;  /* Sector number of disk location. */
//   int open_cnt;           /* Number of openers. */
//   bool removed;           /* True if deleted, false otherwise. */
//   int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
//   struct inode_disk data; /* Inode content. */
// };

// /* Returns the block device sector that contains byte offset POS
//    within INODE.
//    Returns -1 if INODE does not contain data for a byte at offset
//    POS. */
// static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
//   ASSERT(inode != NULL);
//   if (pos < inode->data.length)
//     return inode->data.start + pos / BLOCK_SECTOR_SIZE;
//   else
//     return -1;
// }

// /* List of open inodes, so that opening a single inode twice
//    returns the same `struct inode'. */
// static struct list open_inodes;

// /* Initializes the inode module. */
// void inode_init(void) { list_init(&open_inodes); }

// /* Initializes an inode with LENGTH bytes of data and
//    writes the new inode to sector SECTOR on the file system
//    device.
//    Returns true if successful.
//    Returns false if memory or disk allocation fails. */
// bool inode_create(block_sector_t sector, off_t length) {
//   struct inode_disk* disk_inode = NULL;
//   bool success = false;

//   ASSERT(length >= 0);

//   /* If this assertion fails, the inode structure is not exactly
//      one sector in size, and you should fix that. */
//   ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

//   disk_inode = calloc(1, sizeof *disk_inode);
//   if (disk_inode != NULL) {
//     size_t sectors = bytes_to_sectors(length);
//     disk_inode->length = length;
//     disk_inode->magic = INODE_MAGIC;
//     if (free_map_allocate(sectors, &disk_inode->start)) {
//       block_write(fs_device, sector, disk_inode);
//       if (sectors > 0) {
//         static char zeros[BLOCK_SECTOR_SIZE];
//         size_t i;

//         for (i = 0; i < sectors; i++)
//           block_write(fs_device, disk_inode->start + i, zeros);
//       }
//       success = true;
//     }
//     free(disk_inode);
//   }
//   return success;
// }

// /* Reads an inode from SECTOR
//    and returns a `struct inode' that contains it.
//    Returns a null pointer if memory allocation fails. */
// struct inode* inode_open(block_sector_t sector) {
//   struct list_elem* e;
//   struct inode* inode;

//   /* Check whether this inode is already open. */
//   for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
//     inode = list_entry(e, struct inode, elem);
//     if (inode->sector == sector) {
//       inode_reopen(inode);
//       return inode;
//     }
//   }

//   /* Allocate memory. */
//   inode = malloc(sizeof *inode);
//   if (inode == NULL)
//     return NULL;

//   /* Initialize. */
//   list_push_front(&open_inodes, &inode->elem);
//   inode->sector = sector;
//   inode->open_cnt = 1;
//   inode->deny_write_cnt = 0;
//   inode->removed = false;
//   block_read(fs_device, inode->sector, &inode->data);
//   return inode;
// }

// /* Reopens and returns INODE. */
// struct inode* inode_reopen(struct inode* inode) {
//   if (inode != NULL)
//     inode->open_cnt++;
//   return inode;
// }

// /* Returns INODE's inode number. */
// block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

// /* Closes INODE and writes it to disk.
//    If this was the last reference to INODE, frees its memory.
//    If INODE was also a removed inode, frees its blocks. */
// void inode_close(struct inode* inode) {
//   /* Ignore null pointer. */
//   if (inode == NULL)
//     return;

//   /* Release resources if this was the last opener. */
//   if (--inode->open_cnt == 0) {
//     /* Remove from inode list and release lock. */
//     list_remove(&inode->elem);

//     /* Deallocate blocks if removed. */
//     if (inode->removed) {
//       free_map_release(inode->sector, 1);
//       free_map_release(inode->data.start, bytes_to_sectors(inode->data.length));
//     }

//     free(inode);
//   }
// }

// /* Marks INODE to be deleted when it is closed by the last caller who
//    has it open. */
// void inode_remove(struct inode* inode) {
//   ASSERT(inode != NULL);
//   inode->removed = true;
// }

// /* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
//    Returns the number of bytes actually read, which may be less
//    than SIZE if an error occurs or end of file is reached. */
// off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
//   uint8_t* buffer = buffer_;
//   off_t bytes_read = 0;
//   uint8_t* bounce = NULL;

//   while (size > 0) {
//     /* Disk sector to read, starting byte offset within sector. */
//     block_sector_t sector_idx = byte_to_sector(inode, offset);
//     int sector_ofs = offset % BLOCK_SECTOR_SIZE;

//     /* Bytes left in inode, bytes left in sector, lesser of the two. */
//     off_t inode_left = inode_length(inode) - offset;
//     int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
//     int min_left = inode_left < sector_left ? inode_left : sector_left;

//     /* Number of bytes to actually copy out of this sector. */
//     int chunk_size = size < min_left ? size : min_left;
//     if (chunk_size <= 0)
//       break;

//     if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
//       /* Read full sector directly into caller's buffer. */
//       block_read(fs_device, sector_idx, buffer + bytes_read);
//     } else {
//       /* Read sector into bounce buffer, then partially copy
//              into caller's buffer. */
//       if (bounce == NULL) {
//         bounce = malloc(BLOCK_SECTOR_SIZE);
//         if (bounce == NULL)
//           break;
//       }
//       block_read(fs_device, sector_idx, bounce);
//       memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
//     }

//     /* Advance. */
//     size -= chunk_size;
//     offset += chunk_size;
//     bytes_read += chunk_size;
//   }
//   free(bounce);

//   return bytes_read;
// }

// /* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
//    Returns the number of bytes actually written, which may be
//    less than SIZE if end of file is reached or an error occurs.
//    (Normally a write at end of file would extend the inode, but
//    growth is not yet implemented.) */
// off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
//   const uint8_t* buffer = buffer_;
//   off_t bytes_written = 0;
//   uint8_t* bounce = NULL;

//   if (inode->deny_write_cnt)
//     return 0;

//   while (size > 0) {
//     /* Sector to write, starting byte offset within sector. */
//     block_sector_t sector_idx = byte_to_sector(inode, offset);
//     int sector_ofs = offset % BLOCK_SECTOR_SIZE;

//     /* Bytes left in inode, bytes left in sector, lesser of the two. */
//     off_t inode_left = inode_length(inode) - offset;
//     int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
//     int min_left = inode_left < sector_left ? inode_left : sector_left;

//     /* Number of bytes to actually write into this sector. */
//     int chunk_size = size < min_left ? size : min_left;
//     if (chunk_size <= 0)
//       break;

//     if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
//       /* Write full sector directly to disk. */
//       block_write(fs_device, sector_idx, buffer + bytes_written);
//     } else {
//       /* We need a bounce buffer. */
//       if (bounce == NULL) {
//         bounce = malloc(BLOCK_SECTOR_SIZE);
//         if (bounce == NULL)
//           break;
//       }

//       /* If the sector contains data before or after the chunk
//              we're writing, then we need to read in the sector
//              first.  Otherwise we start with a sector of all zeros. */
//       if (sector_ofs > 0 || chunk_size < sector_left)
//         block_read(fs_device, sector_idx, bounce);
//       else
//         memset(bounce, 0, BLOCK_SECTOR_SIZE);
//       memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
//       block_write(fs_device, sector_idx, bounce);
//     }

//     /* Advance. */
//     size -= chunk_size;
//     offset += chunk_size;
//     bytes_written += chunk_size;
//   }
//   free(bounce);

//   return bytes_written;
// }

// /* Disables writes to INODE.
//    May be called at most once per inode opener. */
// void inode_deny_write(struct inode* inode) {
//   inode->deny_write_cnt++;
//   ASSERT(inode->deny_write_cnt <= inode->open_cnt);
// }

// /* Re-enables writes to INODE.
//    Must be called once by each inode opener who has called
//    inode_deny_write() on the inode, before closing the inode. */
// void inode_allow_write(struct inode* inode) {
//   ASSERT(inode->deny_write_cnt > 0);
//   ASSERT(inode->deny_write_cnt <= inode->open_cnt);
//   inode->deny_write_cnt--;
// }

// /* Returns the length, in bytes, of INODE's data. */
// off_t inode_length(const struct inode* inode) { return inode->data.length; }