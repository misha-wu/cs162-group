/*  Check hit rate */

#include <random.h>
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

#define FILE_SIZE 200
static char buf_a[FILE_SIZE];
static char buf_ch[1];

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
  buf_ch[0] = 'a';

  // random_init(0);
  // random_bytes(buf_a, sizeof buf_a);

  CHECK(create("a", 0), "create \"a\"");

  CHECK((fd_a = open("a")) > 1, "open \"a\"");

  msg("write \"a\"");
  while (ofs_a < FILE_SIZE) {
    ofs_a += write(fd_a, buf_ch, 1);
  }

  //read in byte by byte
  size_t read_ofs_a = 0;

  while (read_ofs_a < FILE_SIZE) {
    read_ofs_a += read(fd_a, buf_ch, 1);
  }

  int writes = filesys_write_cnt();
  int reads = filesys_read_cnt();

  ASSERT(100<writes && writes<200);
  ASSERT(100<reads && reads<200);

}