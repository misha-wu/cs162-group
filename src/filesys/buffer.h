
#include "filesys/filesys.h"
#include <ctype.h>
#include <debug.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "userprog/process.h"
#include "devices/block.h"
// #include <bits/types.h>

typedef struct cache_block {
  struct block* block;
  block_sector_t sector;
  uint8_t contents[BLOCK_SECTOR_SIZE];
  bool dirty; // for write back
  bool use;  // for clock algorithm
  struct lock lock; // when one thread is actively reading/writing to the block, no other thread can evict that block
  struct list_elem elem;
} cache_block_t;

// our cache is a 64-array of cache_block pointers
extern struct cache_block* cache[64];
extern struct lock global_cache_lock;
extern bool free_cache_map[64];
extern int clock_index;

cache_block_t* check_cache(struct block* block, block_sector_t sector);
cache_block_t* cache_read(struct block* block, block_sector_t sector);
void cache_write(struct block* block, block_sector_t sector, const void* buffer);
void cache_read_buffer(struct block* block, block_sector_t sector, const void* buffer);
uint8_t clock_algorithm(void);



