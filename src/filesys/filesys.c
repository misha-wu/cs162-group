#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "userprog/process.h"
#include "filesys/buffer.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

unsigned long long get_filesys_read_cnt() {
  return get_read_cnt(fs_device);
}

unsigned long long get_filesys_write_cnt() {
  return get_write_cnt(fs_device);
}


/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  cache_init();
  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) { 
  free_map_close(); 
  cache_flush();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
  block_sector_t inode_sector = 0;
  struct dir* dir = dir_open_root();
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size) && dir_add(dir, name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);

  return success;
}

bool filesys_create_in_dir(const char* name, off_t initial_size, struct dir* cwd) {
  block_sector_t inode_sector = 0;
  char last_part[NAME_MAX + 1];
  struct dir* dir = get_wo_de_dir(last_part, name, cwd);
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size) && dir_add(dir, last_part, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {
  struct dir* dir = dir_open_root();
  struct inode* inode = NULL;

  if (dir != NULL)
    dir_lookup(dir, name, &inode);
  dir_close(dir);

  return file_open(inode);
}

struct file* filesys_open_in_dir(const char* name, struct dir* cwd) {
  if (strcmp("", name) == 0) {
    return false;
  }
  char last_part[NAME_MAX + 1];
  struct dir* dir;
  if (cwd == NULL) {
    dir = dir_open_root();
  } else {
    dir = get_wo_de_dir(last_part, name, cwd);
  }
  struct inode* inode = NULL;

  if (dir != NULL)
    dir_lookup(dir, last_part, &inode);
  dir_close(dir);

  if (inode == NULL) {
    return NULL;
  }

  struct fd_entry* fde = malloc(sizeof(struct fd_entry));
  if (fde == NULL) {
    return NULL;
  }

  if (get_is_dir(inode)) {
    fde->is_dir = true;
    fde->dir = dir_open(inode);
    fde->file = NULL;
    struct inode* inode = NULL;
  } else {
    fde->is_dir = false;
    fde->dir = NULL;
    fde->file = file_open(inode);
  }

  return fde;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  struct dir* dir = dir_open_root();
  bool success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);

  return success;
}

bool filesys_remove_in_dir(const char* name, struct dir* cwd) {
  if (strcmp("/", name) == 0) {
    return false;
  }
  char last_part[NAME_MAX + 1];
  struct dir* dir = get_wo_de_dir(last_part, name, cwd);
  bool success = dir != NULL && dir_remove(dir, last_part);
  dir_close(dir);

  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}
