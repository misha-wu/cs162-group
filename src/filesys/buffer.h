
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

cache_block_t* check_cache(struct block* block, block_sector_t sector, void* buffer);

// our cache is a 64-array of cache_blocks
struct cache_block cache[64];
bool free_map[64];
int clock_index;

