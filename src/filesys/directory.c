#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
// #include "filesys/directory.h"
#include "userprog/process.h"


/* A directory. */
struct dir {
  struct inode* inode; /* Backing store. */
  off_t pos;           /* Current position. */
  struct dir* parent;
};

/* A single directory entry. */
struct dir_entry {
  block_sector_t inode_sector; /* Sector number of header. */
  char name[NAME_MAX + 1];     /* Null terminated file name. */
  bool in_use;                 /* In use or free? */
};

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
// bool dir_create(block_sector_t sector, size_t entry_cnt) {
//   return inode_create(sector, entry_cnt * sizeof(struct dir_entry));
// }


bool wo_de_dir_create(block_sector_t sector, size_t entry_cnt, struct dir* parent) {
  if (!inode_create_dir(sector, entry_cnt * sizeof(struct dir_entry))) {
    return false;
  }
  struct inode* inode = inode_open(sector);
  struct dir* my_dir = dir_open(inode);
  if (!dir_add(my_dir, ".", sector)) {
    dir_close(my_dir);
    inode_close(inode);
    return false;
  }
  struct inode* inodeeee = NULL;
  // dir_lookup(parent, "parent should have ", &inodeeee);
  if (!dir_add(my_dir, "..", inode_get_inumber(parent->inode))) {
    dir_close(my_dir);
    inode_close(inode);
    return false;
  }
  // printf("open count in wo de dir create is %d\n", get_open_count(inode));
  // if (sector == ROOT_DIR_SECTOR) {
  //   if (!dir_add(my_dir, "/", ROOT_DIR_SECTOR)) {
  //     dir_close(my_dir);
  //     inode_close(inode);
  //     return false;
  //   }
  // }
  dir_close(my_dir);
  inode_close(inode);
  return true;
}

bool dir_create(block_sector_t sector, size_t entry_cnt) {
  // return inode_create_dir(sector, entry_cnt * sizeof(struct dir_entry));
  struct dir* dir = dir_open_root();
  bool success = wo_de_dir_create(sector, entry_cnt, dir);
  dir_close(dir);
  return success;
}

struct inode* get_dir_inode(struct dir* dir) {
  return dir->inode;
}

// bool dir_create_2(block_sector_t sector, size_t entry_cnt, struct dir* parent) {
//   bool success = inode_create(sector, entry_cnt * sizeof(struct dir_entry));
//   if (!success) return false;

// }

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

static char* dice_and_slice(char* old_path) {
  // char* path = malloc(strnlen(old_path));
  // strlcpy(path, old_path, strnlen(old_path));
  // for (int i = strlen(path) - 1; i >= 0; i--) {
  //   if (path[i] == '/') {
  //     while (i >= 0 && path[i] == '/') {
  //       path[i] = 0;
  //       i--;
  //     }
  //     break;
  //   }
  // }
}

// static int get_last_part(char part[NAME_MAX + 1], const char** srcp) {
//   int status;
//   while (status = get_next_part(part, srcp) == 1);
//   return status;
// }

struct dir* get_wo_de_dir(char part[NAME_MAX + 1], const char* filename, struct dir* cwd) {
  // printf("get wo de dir filename %s\n", filename);
  // printf("you're the only one i still know how to see\n");
  struct dir* curr_dir;
  if (filename[0] == '/') {
    curr_dir = dir_open_root();
  } else {
    curr_dir = dir_reopen(cwd);
  }
  if (curr_dir == NULL) {
    return NULL;
  }
  // char part[NAME_MAX + 1];
  // printf("it can be us\n");
  bool was_file;
  int status = get_next_part(part, &filename);
    // printf("status is %d", status);
  if (status == 0) {
    part[0] = '.';
    part[1] = 0;
    // strlcpy(part, filename, 1);
    return curr_dir;
  }
  struct dir* last;
  struct dir* sec_last;
  while (true) {
    if (status == 0) {
      break;
    } else if (status == -1) {
      return NULL;
    }
    // printf("part %s\n", part);
    struct inode* inode;
    // printf("send help\n");
    bool found = dir_lookup(curr_dir, part, &inode);
    // printf("fei niao he yu\n");
    // printf("inode at sector %d", get_sector(inode));
    status = get_next_part(part, &filename);
    if (status == 0) {
      inode_close(inode);
      return curr_dir;
    }
    if (!found) {
      inode_close(inode);
      return NULL;
    }
    // printf("inode at sector %d", get_sector(inode));
    
    bool is_dir = get_is_dir(inode);
    if (!is_dir) {
      printf("panicked at the disco when part was %s\n", part);
      inode_close(inode);
      dir_close(curr_dir);
      return NULL;
      // PANIC("panic at the disco");
    }
    // PANIC("is dir %d", is_dir);
    // dir_close(curr_dir);
    // if (status == 0) {
    //   return inode;
    // }
    // curr_dir = dir_open(inode);
    // if (is_dir) {

    dir_close(curr_dir);
    curr_dir = dir_open(inode);
    // printf("curr dir or smth, inode %x\n", inode);
      // return NULL;
    // }
  }
  dir_close(curr_dir);
  return NULL;
}

// struct dir* get_wo_de_dir(char part[NAME_MAX + 1], const char* filename, struct dir* cwd) {
//   printf("get wo de dir filename %s\n", filename);
//   struct dir* curr_dir;
//   if (filename[0] == '/') {
//     curr_dir = dir_open_root();
//   } else {
//     curr_dir = dir_reopen(cwd);
//   }
//   if (curr_dir == NULL) {
//     return NULL;
//   }
//   // char part[NAME_MAX + 1];
//   bool was_file;
//   int status = get_next_part(part, &filename);
//   struct dir* last;
//   struct dir* sec_last;
//   while (true) {
//     if (status == 0) {
//       break;
//     } else if (status == -1) {
//       return NULL;
//     }
//     printf("part %s\n", part);
//     struct inode* inode;
//     bool found = dir_lookup(curr_dir, part, &inode);
//     // printf("inode at sector %d", get_sector(inode));
//     status = get_next_part(part, &filename);
//     printf("status is %d and found %d\n", status, found);
//     if (!found) {
//       if (status == 0) {
//         // printf("inside the if\n");
//         // struct inode* help = curr_dir->inode;
//         // close(curr_dir);
//         // issues: ref counting
//         return curr_dir;
//       }
//       return NULL;
//     }
//     printf("inode at sector %d", get_sector(inode));
    
//     bool is_dir = get_is_dir(inode);
//     if (!is_dir) {
//       printf("panicked at the disco when part was %s\n", part);
//       return NULL;
//       // PANIC("panic at the disco");
//     }
//     // PANIC("is dir %d", is_dir);
//     // dir_close(curr_dir);
//     // if (status == 0) {
//     //   return inode;
//     // }
//     // curr_dir = dir_open(inode);
//     // if (is_dir) {

//     dir_close(curr_dir);
//     curr_dir = dir_open(inode);
//     printf("curr dir or smth, inode %x\n", inode);
//       // return NULL;
//     // }
//   }
//   dir_close(curr_dir);
//   return NULL;
// }

struct inode* path_resolution_funsies(const char* filename, struct dir* cwd, bool last_should_exist) {
  printf("asldfjkalskdfjalskdfjalds\n");
  struct dir* curr_dir;
  printf("filename[0] is %c\n", *filename);
  if (filename[0] == '/') {
    printf("wgat\n");
    curr_dir = dir_open_root();
  } else {
    printf("should use cwd, inode is %x\n", get_dir_inode(cwd));
    curr_dir = dir_reopen(cwd);
  }
  if (curr_dir == NULL) {
    return NULL;
  }
  char part[NAME_MAX + 1];
  bool was_file;
  int status = get_next_part(part, &filename);
  while (true) {
    
    if (status == 0) {
      break;
    }
    if (status == -1) {
      return NULL;
    }
    printf("part %s\n", part);
    struct inode* inode;
    bool found = dir_lookup(curr_dir, part, &inode);
    status = get_next_part(part, &filename);
    printf("status is %d and found %d\n", status, found);
    if (!found) {
      if (status == 0 && !last_should_exist) {
        printf("inside the if\n");
        struct inode* help = curr_dir->inode;
        // close(curr_dir);
        // issues: ref counting
        return help;
      }
      return NULL;
    }
    
    bool is_dir = get_is_dir(inode);
    dir_close(curr_dir);
    if (status == 0) {
      return inode;
    }
    if (is_dir) {
      curr_dir = dir_open(inode);
    }
  }
  dir_close(curr_dir);
  return NULL;

}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir* dir_open(struct inode* inode) {
  struct dir* dir = calloc(1, sizeof *dir);
  if (inode != NULL && dir != NULL) {
    dir->inode = inode;
    dir->pos = 0;
    return dir;
  } else {
    inode_close(inode);
    free(dir);
    return NULL;
  }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir* dir_open_root(void) {
  return dir_open(inode_open(ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir* dir_reopen(struct dir* dir) {
  return dir_open(inode_reopen(dir->inode));
}

/* Destroys DIR and frees associated resources. */
void dir_close(struct dir* dir) {
  if (dir != NULL) {
    inode_close(dir->inode);
    free(dir);
  }
}

/* Returns the inode encapsulated by DIR. */
struct inode* dir_get_inode(struct dir* dir) {
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool lookup(const struct dir* dir, const char* name, struct dir_entry* ep, off_t* ofsp) {
  struct dir_entry e;
  size_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e) {
    // printf("looking up %s, actual name %s\n", name, e.name);
    if (e.in_use && !strcmp(name, e.name)) {
      if (ep != NULL)
        *ep = e;
      if (ofsp != NULL)
        *ofsp = ofs;
      return true;
    }
  }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool dir_lookup(const struct dir* dir, const char* name, struct inode** inode) {
  struct dir_entry e;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  if (lookup(dir, name, &e, NULL))
    *inode = inode_open(e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool dir_add(struct dir* dir, const char* name, block_sector_t inode_sector) {
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen(name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup(dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy(e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at(dir->inode, &e, sizeof e, ofs) == sizeof e;

  // printf("have supposedly added this to the directory\n");
  lookup(dir, name, NULL, NULL);

done:
  return success;
}

bool dir_is_empty(struct dir* dir) {
  struct dir_entry e;
  size_t ofs;
  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e) {
    // printf("should be empty, name is %solympi\n", e.name);
    if (e.in_use && (strcmp(".", e.name) != 0 && strcmp("..", e.name) != 0)) {
      // printf("inside the if, name is %solympi\n", e.name);
      return false;
    }
  }
  return true;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool dir_remove(struct dir* dir, const char* name) {
  struct dir_entry e;
  struct inode* inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  // printf("before lookup\n");
  /* Find directory entry. */
  if (!lookup(dir, name, &e, &ofs))
    goto done;

  // printf("after lookup\n");
  /* Open inode. */
  inode = inode_open(e.inode_sector);
  // printf("open count after opening is %d\n", get_open_count(inode));
  if (inode == NULL)
    goto done;

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at(dir->inode, &e, sizeof e, ofs) != sizeof e)
    goto done;

  /* Remove inode. */
  // printf("i never thought there'd\n");
  if (get_is_dir(inode)) {
    // printf("open count is %d\n", get_open_count(inode));
    if (get_open_count(inode) > 1) {
      return false;
    }
    // printf("i'm a directory\n");
    struct dir* my_dir = dir_open(inode);
    if (!dir_is_empty(my_dir)) {
      // printf("i'm not empty :(\n");
      dir_close(my_dir);
      return false;
    }
    // printf("i'm empty\n");
    dir_close(my_dir);
  }
  inode_remove(inode);
  success = true;

done:
  inode_close(inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool dir_readdir(struct dir* dir, char name[NAME_MAX + 1]) {
  struct dir_entry e;

  // printf("hello in read dir, dir->pos is %d\n", dir->pos);

  while (inode_read_at(dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
    dir->pos += sizeof e;
    // if (e.in_use) {
    // printf("before in use name %s\n", e.name);
    if (e.in_use && (strcmp(".", e.name) != 0 && strcmp("..", e.name) != 0)) {
      // printf("name %s\n", e.name);
      strlcpy(name, e.name, NAME_MAX + 1);
      return true;
    }
  }
  return false;
}
