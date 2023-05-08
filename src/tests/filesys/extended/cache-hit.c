/*  Check hit rate */

#include <random.h>
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

#define FILE_SIZE 4096
static char buf_a[FILE_SIZE];
// static char buf_b[FILE_SIZE];

static void write_some_bytes(const char* file_name, int fd, const char* buf, size_t* ofs) {
  if (*ofs < FILE_SIZE) {
    size_t block_size = random_ulong() % (FILE_SIZE / 8) + 1;
    size_t ret_val;
    if (block_size > FILE_SIZE - *ofs)
      block_size = FILE_SIZE - *ofs;

    ret_val = write(fd, buf + *ofs, block_size);
    if (ret_val != block_size)
      fail("write %zu bytes at offset %zu in \"%s\" returned %zu", block_size, *ofs, file_name,
           ret_val);
    *ofs += block_size;
  }
}

void test_main(void) {
  int fd_a;
  size_t ofs_a = 0;

  random_init(0);
  random_bytes(buf_a, sizeof buf_a);

  CHECK(create("a", 0), "create \"a\"");

  CHECK((fd_a = open("a")) > 1, "open \"a\"");

  msg("write \"a\"");
  while (ofs_a < FILE_SIZE) {
    write_some_bytes("a", fd_a, buf_a, &ofs_a);
  }
  msg("flush cache");
  flush_cache();

  int accesses = get_cache_accesses();
  int hits = get_cache_hits();
  ASSERT(accesses == 0);
  ASSERT(hits == 0);
  
  msg("read \"a\"");
  read(fd_a, buf_a, 1024);
  accesses = get_cache_accesses();
  hits = get_cache_hits();
  float rate1 = (float) (hits)/accesses;
  
  msg("close \"a\"");
  close(fd_a);
  CHECK((fd_a = open("a")) > 1, "open \"a\"");

  msg("read \"a\"");
  read(fd_a, buf_a, 1024);
  
  accesses = get_cache_accesses();
  hits = get_cache_hits();
  float rate2 = (float) (hits)/accesses;
  msg("close \"a\"");
  close(fd_a);

  msg("compare hit rates");
  ASSERT(rate2 > rate1);

}