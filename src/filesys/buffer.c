#include "buffer.h"

cache_block_t* check_cache(struct block* block, block_sector_t sector, void* buffer) {
    for (int i = 0; i < 64; i++) {
        cache_block_t cache_block = cache[i];
        if (&cache_block.block == block & cache_block.sector == sector) { // can i compare blocks like this?? 
            lock_acquire(&cache_block.lock);
            memcpy(buffer, cache_block.contents, sizeof(cache_block.contents));
            cache_block.use = true;
            lock_release(&cache_block.lock);
            return &cache_block;
        }
    }
    return NULL;
}

