#include "buffer.h"

struct cache_block* cache[64];
struct lock global_cache_lock;
int total_cache_accesses;
int total_cache_hits;
bool free_cache_map[64];
int clock_index;

void cache_init() {
  lock_init(&global_cache_lock);
  total_cache_accesses = 0;
  total_cache_hits = 0;
  for (int i = 0; i < 64; i++) {
    free_cache_map[i] = true;
    cache[i] = NULL;
  }
  clock_index = 0;
}

void cache_flush() {
  total_cache_accesses = 0;
  total_cache_hits = 0;
  clock_index = 0;

  for (int i = 0; i < 64; i++) {
    if (cache[i] == NULL) {
      continue;
    }
    if (cache[i]->dirty) {
      block_write(cache[i]->block, cache[i]->sector, cache[i]->contents);
    }
    free(cache[i]);
    cache[i] = NULL;
  }

  for (int i = 0; i < 64; i++) {
    free_cache_map[i] = true;
  }
}

cache_block_t* check_cache(struct block* block, block_sector_t sector) {
    for (int i = 0; i < 64; i++) {
        cache_block_t* cache_block = cache[i];
        if (cache[i] == NULL) {
            continue;
        }
        lock_acquire(&global_cache_lock);
        if (cache_block->sector == sector) { 
            cache_block->use = true;
            lock_release(&global_cache_lock);
            return cache_block;
        }
        lock_release(&global_cache_lock);
    }
    return NULL;
}


void* cache_read_ret(struct block* block, block_sector_t sector) {
    return cache_read(block, sector)->contents;
}

cache_block_t* cache_read_inner(struct block* block, block_sector_t sector) {
    cache_block_t* cache_block = calloc(1, sizeof(cache_block_t));
    cache_block->block = block;
    cache_block->sector = sector;
    cache_block->use = true;
    cache_block->dirty = false;
    lock_init(&cache_block->lock);

    block_read(block, sector, &cache_block->contents);
    lock_acquire(&global_cache_lock);
    for (int i = 0; i < 64; i++) {
        if (free_cache_map[i]) {
            free_cache_map[i] = false;
            cache[i] = cache_block;
            lock_release(&global_cache_lock);
            return cache_block;
        }
    }
    lock_release(&global_cache_lock);
    
    uint8_t evict_index;
    cache_block_t* to_evict;
    while (true) {
        lock_acquire(&global_cache_lock);
        evict_index = clock_algorithm();
        to_evict = cache[evict_index];
        block_sector_t evict_sector = cache[evict_index]->sector;
        lock_release(&global_cache_lock);
        if (lock_try_acquire(&to_evict->lock)) {
            if (evict_sector != cache[evict_index]->sector) {
                lock_release(&to_evict->lock);
            } else {
                if (to_evict->dirty) {
                    block_write(to_evict->block, to_evict->sector, to_evict->contents);
                }
                cache[evict_index] = cache_block;
                lock_release(&to_evict->lock);
                free(to_evict);
                break;
            }
        }
    }
    return cache_block;

}

cache_block_t* cache_read(struct block* block, block_sector_t sector) {
    cache_block_t* in_cache = check_cache(block, sector);
    lock_acquire(&global_cache_lock);
    total_cache_accesses++;
    lock_release(&global_cache_lock);
    
    if (in_cache != NULL) {
        lock_acquire(&global_cache_lock);
        total_cache_hits ++;
        lock_release(&global_cache_lock);
        return in_cache;
    }

    cache_block_t* cache_block = calloc(1, sizeof(cache_block_t));
    cache_block->block = block;
    cache_block->sector = sector;
    cache_block->use = true;
    cache_block->dirty = false;
    lock_init(&cache_block->lock);

    block_read(block, sector, &cache_block->contents);

    lock_acquire(&global_cache_lock);
    for (int i = 0; i < 64; i++) {
        if (free_cache_map[i]) {
            free_cache_map[i] = false;
            cache[i] = cache_block;
            lock_release(&global_cache_lock);
            return cache_block;
        }
    }
    lock_release(&global_cache_lock);
    
    uint8_t evict_index;
    cache_block_t* to_evict;
    while (true) {
        lock_acquire(&global_cache_lock);
        evict_index = clock_algorithm();
        to_evict = cache[evict_index];
        block_sector_t evict_sector = cache[evict_index]->sector;
        lock_release(&global_cache_lock);
        if (lock_try_acquire(&to_evict->lock)) {
            if (evict_sector != cache[evict_index]->sector) {
                lock_release(&to_evict->lock);
            } else {
                if (to_evict->dirty) {
                    block_write(to_evict->block, to_evict->sector, to_evict->contents);
                }
                cache[evict_index] = cache_block;
                lock_release(&to_evict->lock);
                free(to_evict);
                break;
            }
        }
    }
    
    return cache_block;

}

int sys_get_cache_accesses() {
    return total_cache_accesses;
}

int sys_get_cache_hits() {
    return total_cache_hits;
}

void cache_write(struct block* block, block_sector_t sector, const void* buffer) {
    cache_block_t* cache_block = cache_read(block, sector);
    lock_acquire(&cache_block->lock);
    memcpy(cache_block->contents, buffer, BLOCK_SECTOR_SIZE);
    cache_block->dirty = true;
    lock_release(&cache_block->lock);
}

uint8_t clock_algorithm(void) { 
    while (true) {
        if (!cache[clock_index]->use) {
            return clock_index;
        }
        cache[clock_index]->use = false;
        clock_index = (clock_index + 1) % 64;
    }
}