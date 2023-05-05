#include "buffer.h"

cache_block_t* check_cache(struct block* block, block_sector_t sector, void* buffer) {
    for (int i = 0; i < 64; i++) {
        cache_block_t* cache_block = cache[i];
        if (&cache_block->block == block & cache_block->sector == sector) { // can i compare blocks like this?? 
            lock_acquire(&cache_block->lock);
            memcpy(buffer, cache_block->contents, sizeof(cache_block->contents));
            cache_block->use = true;
            lock_release(&cache_block->lock);
            return &cache_block;
        }
    }
    return NULL;
}

cache_block_t* cache_read(struct block* block, block_sector_t sector, void* buffer) {
    cache_block_t* in_cache = check_cache(block, sector, buffer);
    
    if (in_cache != NULL) {
        return in_cache;
    }

    cache_block_t* cache_block = calloc(1, sizeof(cache_block_t));
    cache_block->block = block;
    cache_block->sector = sector;
    cache_block->use = true;
    cache_block->dirty = false;
    lock_init(&cache_block->lock);

    block_read(block, sector, &cache_block->contents);
    memcpy(buffer, cache_block->contents, sizeof(cache_block->contents));

    // TOOD ?? global lock or smth
    lock_acquire(&global_cache_lock);
    for (int i = 0; i < 64; i++) {
        if (free_map[i]) {
            // TODO do some locking
            free_map[i] = false;
            cache[i] = cache_block;
            // TODO do some unlocking
            return cache_block;
        }
    }
    lock_release(&global_cache_lock);

    // now we need to evict :(
    uint8_t evict_index = clock_algorithm();
    cache_block_t* to_evict = cache[evict_index];
    lock_acquire(&to_evict->lock);
    if (to_evict->dirty) {
        block_write(to_evict->block, to_evict->sector, to_evict->contents);
    }
    cache[evict_index] = cache_block;
    lock_release(&to_evict->lock);
    
    return cache_block;

}

void cache_write(struct block* block, block_sector_t sector, const void* buffer) {
    cache_block_t* cache_block = cache_read(block, sector, buffer);
    memcpy(cache_block->contents, buffer, sizeof(buffer));
    cache_block->dirty = true;
}

// TODO dont forget to initialize clock index to 0 somewhere prob filesys init or smth
uint8_t clock_algorithm(void) { 
    while (true) {
        if (!cache[clock_index]->use) {
            return clock_index;
        }
        cache[clock_index]->use = false;
        clock_index = (clock_index + 1) % 64;
    }
}