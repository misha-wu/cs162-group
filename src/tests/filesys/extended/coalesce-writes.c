/*  Check hit rate */

#include <random.h>
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

#define FILE_SIZE 65536
static char buf_a[FILE_SIZE];

// Test your buffer cache’s ability to 
// coalesce writes to the same sector. 
// Each block device keeps a read_cnt counter 
// and a write_cnt counter. 
// Write a large large file at least 64 KiB 
// (i.e. twice the maximum allowed buffer cache size) byte-by-byte. 
// Then, read it in byte-by-byte. 
// The total number of device writes should be on the order of 128 since 64 KiB is 128 blocks.
void test_main(void) {
  int fd_a;
  size_t ofs_a = 0;

  random_init(0);
  random_bytes(buf_a, sizeof buf_a);
  // random_bytes(buf_b, sizeof buf_b);

  CHECK(create("a", 0), "create \"a\"");
  // CHECK(create("b", 0), "create \"b\"");

  CHECK((fd_a = open("a")) > 1, "open \"a\"");
  // CHECK((fd_b = open("b")) > 1, "open \"b\"");

  msg("write \"a\"");
  while (ofs_a < FILE_SIZE) {
    ofs_a += write(fd_a, buf_a, 1);
  }

  //read in byte by byte
  size_t read_ofs_a = 0;

  while (read_ofs_a < FILE_SIZE) {
    read_ofs_a += read(fd_a, buf_a, 1);
  }

  int writes = filesys_write_cnt();
  int reads = filesys_read_cnt();

  ASSERT(100<writes<200);
  ASSERT(100<reads<200);

}