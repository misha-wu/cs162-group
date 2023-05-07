#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

#include "lib/string.h"
#include "filesys/directory.h"
#include "filesys/inode.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { 
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); 
  }

// helper function to get pcb of current process
struct process* process_current(void) {
  struct thread* t = thread_current();
  return t->pcb;
}

struct dir* get_cwd() {
  return dir_reopen(process_current()->cwd);
}

// checks file descriptor is valid
bool valid_fd(int fd) {
  struct process* p = process_current();
  if (fd == 0 || fd == 1 || fd == 2) {
    return true;
  }
  if (fd >= p->fd_index || p->fd_table[fd] == NULL) {
    return false;
  }
  return true;
}

//this is a comphrehensive check; make sure you really need all the fields
//user address + has been initialized
bool valid_address(void* address) {
  if (address == NULL || !is_user_vaddr(address)) {
    return false;
  }
  struct process* p = process_current();
  void* phys_addr = pagedir_get_page(p->pagedir, address);
  if (phys_addr == NULL) {
    return false;
  }
  return true;
}

// exit syscall
int exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
  exit_helper(status);
  return status;
}

// create syscall
int create(char* filename, unsigned initial_size) {
  if (filename == NULL) {
    exit(-1);
  // check conditions and try to create, which will return false if failed 
  } else {
    struct process* p = process_current();
    if (p->fd_index + 1 >= NUM_FDS) {
      return 0;
    }
    if (strlen(filename) > 256) {
      return 0;
    }
    struct dir* cwd = get_cwd();
    bool success = filesys_create_in_dir(filename, initial_size, cwd);
    dir_close(cwd);
    return success;
  }
  return 0;
}

// open syscall
int open (char *name) {
  if (name == NULL) {
    return -1;
  }
  struct dir* cwd = get_cwd();
  struct fd_entry* fde = filesys_open_in_dir(name, cwd);
  dir_close(cwd);
  
  if (fde == NULL) {
    return -1;
  }
  struct process* p = process_current();
  if (strcmp(p->process_name, name) == 0 && fde->file != NULL) {
    file_deny_write(fde->file);
  }
  // add file to fd table and increment next available fd
  if (p->fd_index + 1 >= NUM_FDS) {
    return -1;
  }
  int fd = p->fd_index;
  p->fd_table[fd] = fde;
  p->fd_index++;  
  return fd;
}

// remove syscall
bool remove (const char *file) {
  if (file == NULL) {
    return NULL;
  }
  struct dir* cwd = get_cwd();  
  bool success = filesys_remove_in_dir(file, cwd);
  dir_close(cwd);
  return success;
}

// filesize syscall
int filesize (int fd) {
  if (!valid_fd(fd)) {
    return -1;
  }
  struct process* p = process_current();
  struct fd_entry* fde = p->fd_table[fd];
  if (fde->is_dir) {
    return -1;
  }
  int file_len = file_length(fde->file);
  return file_len;
}

// read syscall
int read (int fd, void *buffer, unsigned size) {
  if (!valid_fd(fd)) {
    return -1;
  }
  if (!valid_address(buffer)) {
    exit(-1);
  }
  int num_read = 0;
  // read from stdin
  if (fd == 0) {
    char* cbuf = (char*) buffer;
    // iterate through and get characters until we reach the desired size
    for (unsigned int i = 0; i < size; i++) {
      uint8_t c = input_getc();
      if (c == -1) {
        break;
      }
      *cbuf = c;
      cbuf++;
      num_read++;
    }
    return num_read;
  }
  // read from a file that is not stdin by calling the appropriate function
  struct fd_entry* fde = process_current()->fd_table[fd];
  if (fde->is_dir) {
    return -1;
  }
  num_read = file_read(fde->file, buffer, size);
  return num_read;
}

// write syscall
int write (int fd, const void *buffer, unsigned size) {
  if (fd != 1 && !valid_fd(fd)) {
    return -1;
  }
  if (!valid_address(buffer)) {
    exit(-1);
  }
  // write to stdout
  if (fd == 1) {
    unsigned int max_buf_size = 200;
    // write at most max_buf_size characters at a time, keep looping until have written desired size
    for (int i = 0; i * max_buf_size < size; i++) {
      int min = size;
      if (max_buf_size < size)
        min = max_buf_size;
      putbuf(buffer + i * max_buf_size, min);
    }
    return size;
  }
  // write to a file that is not stdout by calling the appropriate function
  struct fd_entry* fde = process_current()->fd_table[fd];
  if (fde->is_dir) {
    return -1;
  }
  int num_wrote = file_write(fde->file, buffer, size);
  if (num_wrote < 0) {
    return 0;
  }
  return num_wrote;
}

// seek syscall
void seek(int fd, unsigned position) {
  if (!valid_fd(fd)) {
    return;
  }
  struct fd_entry* fde = process_current()->fd_table[fd];
  if (fde->is_dir) {
    return -1;
  }
  file_seek(fde->file, position);
}

// tell syscall
unsigned tell(int fd) {
  if (!valid_fd(fd)) {
    return -1;
  }
  struct fd_entry* fde = process_current()->fd_table[fd];
  if (fde->is_dir) {
    return -1;
  }
  off_t ret = file_tell(fde->file);
  return ret;
}

// close syscall
void close(int fd) {
  if (!valid_fd(fd)) {
    return;
  }
  struct fd_entry* fde = process_current()->fd_table[fd];
  if (fde->is_dir) {
    dir_close(fde->dir);
  } else {
    file_close(fde->file);
  }
  free(fde);

  // mark that a fd has been closed by setting it to null
  process_current()->fd_table[fd] = NULL;  
}

// compute_e syscall
double compute_e (int n) {
  if (n < 0) {
    return -1;
  }
  return sys_sum_to_e(n);
}

bool mkdir(const char* dir) {
  struct dir* cwd = get_cwd();
  char last_part[NAME_MAX + 1];
  struct dir* directory = get_wo_de_dir(last_part, dir, cwd);
  if (directory == NULL) {
    dir_close(cwd);
    return false;
  }
  block_sector_t sector;
  if (!free_map_allocate(1, &sector)) {
    return false;
  }
  wo_de_dir_create(sector, 16, cwd);
  dir_close(cwd);
  if (!dir_add(directory, last_part, sector)) {
    dir_close(directory);
    return false;
  }
  dir_close(directory);
  return true;
}

bool chdir(const char* dir) {
  struct inode* inode = NULL;
  struct dir* cwd = get_cwd();
  char* scuffed = malloc(strlen(dir) + 3);
  snprintf(scuffed, strlen(scuffed), "%s/x", dir);
  char last_part[NAME_MAX + 1];

  struct dir* directory = get_wo_de_dir(last_part, scuffed, cwd);
  free(scuffed);
  dir_close(cwd);
  if (directory == NULL) {
    return false;
  }
  dir_close(process_current()->cwd);
  process_current()->cwd = directory;
  return true;

}

bool readdir(int fd, char* name) {
  if (!valid_fd(fd)) {
    return false;
  }
  struct process* p = process_current();
  struct fd_entry* fde = p->fd_table[fd];
  if (!fde->is_dir) {
    return false;
  }
  bool success = dir_readdir(fde->dir, name);
  return success;
}

int inumber(int fd) {
  if (!valid_fd(fd)) {
    return -1;
  }
  struct fd_entry* fde = process_current()->fd_table[fd];
  struct inode* inode;
  if (!fde->is_dir) {
    inode = file_get_inode(fde->file);
  } else {
    inode = dir_get_inode(fde->dir);
  }
  return inode_get_inumber(inode);
}

bool isdir(int fd) {
  if (!valid_fd(fd)) {
    return false;
  }
  struct fd_entry* fde = process_current()->fd_table[fd];
  bool isdir = fde->is_dir;
  return isdir;
}

/*
call helper, which does argument checking.
*/
static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  if (args[0] == SYS_EXIT) {
    if(!is_user_vaddr((const void*) args[1])) {
      f->eax = exit(-1);
    }
    f->eax = exit(args[1]);
  } else if (args[0] == SYS_PRACTICE) {
    f->eax = args[1] + 1;
  } else if (args[0] == SYS_HALT) {
    shutdown_power_off();
  } else if (args[0] == SYS_EXEC) {
    f->eax = process_execute((const char*) args[1]);
  } else if (args[0] == SYS_WAIT) {
    f->eax = process_wait(args[1]);
  } else if (args[0] == SYS_CREATE) {
    char* filename = (char*) args[1];
    unsigned initial_size = (unsigned) args[2];
    f->eax = create(filename, initial_size);
  } else if (args[0] == SYS_OPEN) {
    char* name = (char*) args[1];
    f->eax = open(name);
  } else if (args[0] == SYS_CLOSE) {
    int fd = args[1];
    close(fd);
  } else if (args[0] == SYS_REMOVE) {
    char* name = (char*) args[1];
    f->eax = remove(name);
  } else if (args[0] == SYS_FILESIZE) {
    int fd = args[1];
    f->eax = filesize(fd);
  } else if (args[0] == SYS_SEEK) {
    int fd = args[1];
    unsigned position = args[2];
    seek(fd, position);
  } else if (args[0] == SYS_TELL) {
    int fd = args[1];
    f->eax = tell(fd);
  } else if (args[0] == SYS_READ) {
    f->eax = read(args[1], (void *) args[2], (unsigned) args[3]);
  } else if (args[0] == SYS_WRITE) {
    int fd = args[1];
    char* buffer = (char *) args[2];
    unsigned size = (unsigned) args[3];
    f->eax = write(fd, buffer, size);
  } else if (args[0] == SYS_COMPUTE_E) {
    f->eax = compute_e(args[1]);
  } else if (args[0] == SYS_MKDIR) {
    f->eax = mkdir(args[1]);
  } else if (args[0] == SYS_CHDIR) {
    f->eax = chdir(args[1]);
  } else if (args[0] == SYS_READDIR) {
    f->eax = readdir(args[1], args[2]);
  } else if (args[0] == SYS_INUMBER) {
    f->eax = inumber(args[1]);
  } else if (args[0] == SYS_ISDIR) {
    f->eax = isdir(args[1]);
  } else if (args[0] == SYS_ACCESSNUM) {
    f->eax = sys_get_cache_accesses();
  } else if (args[0] == SYS_HITNUM) {
    f->eax = sys_get_cache_hits();
  } else if (args[0] == SYS_FLUSH) {
    cache_flush();
  }
}
