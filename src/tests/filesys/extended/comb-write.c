#include <random.h>
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

#define FILE_SIZE 65536
static char buf_a[FILE_SIZE];
static char buf_res[FILE_SIZE];
static char buf_ch[1];


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

  random_init(0);
  random_bytes(buf_a, sizeof buf_a);

  CHECK(create("a", 0), "create \"a\"");

  CHECK((fd_a = open("a")) > 1, "open \"a\"");

  msg("write \"a\"");
  while (ofs_a < FILE_SIZE) {
    ofs_a += write(fd_a, buf_a + ofs_a, 1);
  }

  seek(fd_a, 0);
  size_t read_ofs_a = 0;

  while (read_ofs_a < FILE_SIZE) {
    read_ofs_a += read(fd_a, buf_res+read_ofs_a, 1);
  }

  int writes = filesys_write_cnt();
  int reads = filesys_read_cnt();

  msg("compare device stats");

  ASSERT(writes<1000);
  ASSERT(reads<1000);

  seek(fd_a, 0);

  msg("compare correctness");


  check_file_handle(fd_a, "a", buf_a, 65536);
  close(fd_a);
}