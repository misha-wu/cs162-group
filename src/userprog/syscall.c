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

// global file system lock
struct lock global_file_lock;

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { 
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); 
  lock_init(&global_file_lock);
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
  //  get_wo_de_dir(filename, get_cwd());
  // lock_acquire(&global_file_lock);
  if (filename == NULL) {
    // lock_release(&global_file_lock);
    exit(-1);
  // check conditions and try to create, which will return false if failed 
  } else {
    struct process* p = process_current();
    // printf("fd index %d\n", p->fd_index);
    if (p->fd_index >= 511) {
      // lock_release(&global_file_lock);
      return 0;
    }
    if (strlen(filename) > 256) {
      // lock_release(&global_file_lock);
      return 0;
    }
    struct dir* cwd = get_cwd();
    bool success = filesys_create_in_dir(filename, initial_size, cwd);
    dir_close(cwd);
    // lock_release(&global_file_lock);
    // printf("create succeeded %d\n", success);
    return success;
  }
  return 0;
}

// open syscall
int open (char *name) {
  // lock_acquire(&global_file_lock);
  if (name == NULL) {
    // lock_release(&global_file_lock);
    return -1;
  }
  // printf("in open\n");
  struct dir* cwd = get_cwd();
  // struct file* file = filesys_open_in_dir(name, cwd);
  struct fd_entry* fde = filesys_open_in_dir(name, cwd);
  dir_close(cwd);
  // printf("file is %x\n", file);
  
  if (fde == NULL) {
    // lock_release(&global_file_lock);
    return -1;
  }
  struct process* p = process_current();
  if (strcmp(p->process_name, name) == 0 && fde->file != NULL) {
    file_deny_write(fde->file);
  }
  // add file to fd table and increment next available fd
  if (p->fd_index >= 511) {
    // lock_release(&global_file_lock);
    return -1;
  }
  int fd = p->fd_index;
  // p->fd_table[fd] = file;
  p->fd_table[fd] = fde;
  p->fd_index++;

  // printf("opened %s, is dir %d\n", name, fde->is_dir);
  
  // lock_release(&global_file_lock);
  return fd;
}

// remove syscall
bool remove (const char *file) {
  // printf("in remove syscall :')\n");
  // lock_acquire(&global_file_lock);
  if (file == NULL) {
    // lock_release(&global_file_lock);
    return NULL;
  }
  // lock_release(&global_file_lock);
  // printf("before get cwd in remove\n");
  struct dir* cwd = get_cwd();  
  bool success = filesys_remove_in_dir(file, cwd);
  dir_close(cwd);
  return success;
}

// filesize syscall
int filesize (int fd) {
  // lock_acquire(&global_file_lock);
  if (!valid_fd(fd)) {
    // lock_release(&global_file_lock);
    return -1;
  }
  struct process* p = process_current();
  struct fd_entry* fde = p->fd_table[fd];
  if (fde->is_dir) {
    // lock_release(&global_file_lock);
    return -1;
  }
  // int file_len = file_length(p->fd_table[fd]);
  int file_len = file_length(fde->file);
  // lock_release(&global_file_lock);
  return file_len;
}

// read syscall
int read (int fd, void *buffer, unsigned size) {
  // lock_acquire(&global_file_lock);
  if (!valid_fd(fd)) {
    // lock_release(&global_file_lock);
    return -1;
  }
  if (!valid_address(buffer)) {
    // lock_release(&global_file_lock);
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
    // lock_release(&global_file_lock);
    return num_read;
  }
  // read from a file that is not stdin by calling the appropriate function
  // struct file* file = process_current()->fd_table[fd];
  // num_read = file_read(file, buffer, size);
  struct fd_entry* fde = process_current()->fd_table[fd];
  if (fde->is_dir) {
    // lock_release(&global_file_lock);
    return -1;
  }
  num_read = file_read(fde->file, buffer, size);
  // lock_release(&global_file_lock);
  return num_read;
}

// write syscall
int write (int fd, const void *buffer, unsigned size) {
  // lock_acquire(&global_file_lock);
  if (fd != 1 && !valid_fd(fd)) {
    // lock_release(&global_file_lock);
    return -1;
  }
  if (!valid_address(buffer)) {
    // lock_release(&global_file_lock);
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
    // lock_release(&global_file_lock);
    return size;
  }
  // write to a file that is not stdout by calling the appropriate function
  // struct file* my_file = process_current()->fd_table[fd];
  // int num_wrote = file_write(my_file, buffer, size);
  struct fd_entry* fde = process_current()->fd_table[fd];
  if (fde->is_dir) {
    // lock_release(&global_file_lock);
    return -1;
  }
  int num_wrote = file_write(fde->file, buffer, size);
  // lock_release(&global_file_lock);
  if (num_wrote < 0) {
    return 0;
  }
  return num_wrote;
}

// seek syscall
void seek(int fd, unsigned position) {
  // lock_acquire(&global_file_lock);
  if (!valid_fd(fd)) {
    // lock_release(&global_file_lock);
    return;
  }
  // struct file* file = process_current()->fd_table[fd];
  // file_seek(file, position);
  struct fd_entry* fde = process_current()->fd_table[fd];
  if (fde->is_dir) {
    // lock_release(&global_file_lock);
    return -1;
  }
  file_seek(fde->file, position);
  // lock_release(&global_file_lock);
}

// tell syscall
unsigned tell(int fd) {
  // lock_acquire(&global_file_lock);
  if (!valid_fd(fd)) {
    // lock_release(&global_file_lock);
    return -1;
  }
  // struct file* my_file = process_current()->fd_table[fd];
  // off_t ret = file_tell(my_file);
  struct fd_entry* fde = process_current()->fd_table[fd];
  if (fde->is_dir) {
    // lock_release(&global_file_lock);
    return -1;
  }
  off_t ret = file_tell(fde->file);
  // lock_release(&global_file_lock);
  return ret;
}

// close syscall
void close(int fd) {
  // lock_acquire(&global_file_lock);
  if (!valid_fd(fd)) {
    // lock_release(&global_file_lock);
  } else {
    // struct file* file = process_current()->fd_table[fd];
    // file_close(file);

    struct fd_entry* fde = process_current()->fd_table[fd];
    if (fde->is_dir) {
      dir_close(fde->dir);
    } else {
      file_close(fde->file);
    }
    free(fde);

    // mark that a fd has been closed by setting it to null
    process_current()->fd_table[fd] = NULL;
    // lock_release(&global_file_lock);
  }
}

// compute_e syscall
double compute_e (int n) {
  if (n < 0) {
    return -1;
  }
  return sys_sum_to_e(n);
}

bool mkdir(const char* dir) {
  // printf("lskfjlakjsdflja\n");
  struct dir* cwd = get_cwd();
  char last_part[NAME_MAX + 1];
  struct dir* directory = get_wo_de_dir(last_part, dir, cwd);
  // free(diced);
  if (directory == NULL) {
    dir_close(cwd);
    return false;
  }
  // printf("2\n");
  block_sector_t sector;
  if (!free_map_allocate(1, &sector)) {
    return false;
  }
  // dir_create(sector, 16);
  wo_de_dir_create(sector, 16, cwd);
  dir_close(cwd);
  if (!dir_add(directory, last_part, sector)) {
    dir_close(directory);
    // printf("dir add failed :(\n");
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
  // printf("hi in readdir\n");
  // lock_acquire(&global_file_lock);
  if (!valid_fd(fd)) {
    // lock_release(&global_file_lock);
    return false;
  }
  struct process* p = process_current();
  struct fd_entry* fde = p->fd_table[fd];
  if (!fde->is_dir) {
    // printf("not a directory\n");
    // lock_release(&global_file_lock);
    return false;
  }
  // lock_release(&global_file_lock);
  // printf("hi2\n");
  bool success = dir_readdir(fde->dir, name);
  // printf("success %d\n", success);
  // printf("read name %s\n", name);
  return success;
}

int inumber(int fd) {
  // lock_acquire(&global_file_lock);
  if (!valid_fd(fd)) {
    // lock_release(&global_file_lock);
    return -1;
  }
  struct fd_entry* fde = process_current()->fd_table[fd];
  struct inode* inode;
  if (!fde->is_dir) {
    inode = file_get_inode(fde->file);
  } else {
    inode = dir_get_inode(fde->dir);
  }
  // struct inode* inode = process_current()->fd_table[fd]->inode;
  // lock_release(&global_file_lock);
  return inode_get_inumber(inode);
}

bool isdir(int fd) {
  // lock_acquire(&global_file_lock);
  if (!valid_fd(fd)) {
    // lock_release(&global_file_lock);
    return false;
  }
  struct fd_entry* fde = process_current()->fd_table[fd];
  bool isdir = fde->is_dir;
  // lock_release(&global_file_lock);
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
    // printf("i hate everything\n");
    f->eax = mkdir(args[1]);
  } else if (args[0] == SYS_CHDIR) {
    // printf("henln\n");
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
  } else if (args[0] == SYS_WRITECNT) {
    return get_filesys_write_cnt();
  } else if (args[0] == SYS_READCNT) {
    return get_filesys_read_cnt();
  }
}
