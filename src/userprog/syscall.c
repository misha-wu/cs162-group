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


struct lock global_file_lock;

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { 
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); 
  lock_init(&global_file_lock);
  }

struct process* process_current(void) {
  struct thread* t = thread_current();
  return t->pcb;
}

void exit_helper(int exit_code) {
  struct thread* cur = thread_current();
  process_status_t* mine = cur->pcb->my_own;
  mine->exit_code = exit_code;
  // printf("I am exiting thread %s with exit code %d\n", cur->name, mine->exit_code); //testing error msg
  process_exit();
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

int exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
  exit_helper(status);
  return status;
}

int create(char* filename, unsigned initial_size) {
  lock_acquire(&global_file_lock);
  if (filename == NULL) {
    lock_release(&global_file_lock);
    exit(-1);
  } else if (strlen(filename) > 256 || !filesys_create(filename, initial_size)) {
    lock_release(&global_file_lock);
    return 0;
  } else {
    lock_release(&global_file_lock);
    return 1;
  }
  return 1;
}

int open (char *name) {
  lock_acquire(&global_file_lock);
  if (name == NULL) {
    lock_release(&global_file_lock);
    return -1;
  }
  struct file* file = filesys_open(name);
  
  if (file == NULL) {
    lock_release(&global_file_lock);
    return -1;
  }
  struct process* p = process_current();
  if (strcmp(p->process_name, name) == 0) {
    file_deny_write(file);
  }
  int fd = p->fd_index;
  p->fd_table[fd] = file;
  p->fd_index++;
  lock_release(&global_file_lock);
  return fd;
}

bool remove (const char *file) {
  lock_acquire(&global_file_lock);
  if (file == NULL) {
    lock_release(&global_file_lock);
    return NULL;
  }
  lock_release(&global_file_lock);
  return filesys_remove(file);
}


int filesize (int fd) {
  lock_acquire(&global_file_lock);
  if (!valid_fd(fd)) {
    lock_release(&global_file_lock);
    return -1;
  }
  struct process* p = process_current();
  int file_len = file_length(p->fd_table[fd]);
  lock_release(&global_file_lock);
  return file_len;
}


int read (int fd, void *buffer, unsigned size) {
  lock_acquire(&global_file_lock);
  if (!valid_fd(fd)) {
    lock_release(&global_file_lock);
    return -1;
  }
  if (!valid_address(buffer)) {
    lock_release(&global_file_lock);
    exit(-1);
  }
  int num_read = 0;
  if (fd == 0) {
    char* cbuf = (char*) buffer;
    for (unsigned int i = 0; i < size; i++) {
      uint8_t c = input_getc();
      if (c == -1) {
        break;
      }
      *cbuf = c;
      cbuf++;
      num_read++;
    }
    lock_release(&global_file_lock);
    return num_read;
  }
  struct file* file = process_current()->fd_table[fd];
  num_read = file_read(file, buffer, size);
  lock_release(&global_file_lock);
  return num_read;
}


int write (int fd, const void *buffer, unsigned size) {
  lock_acquire(&global_file_lock);
  if (fd != 1 && !valid_fd(fd)) {
    lock_release(&global_file_lock);
    return -1;
  }
  if (!valid_address(buffer)) {
    lock_release(&global_file_lock);
    exit(-1);
  }
  if (fd == 1) {
    // change if needed? we don't know how big a few hundred is :')
    unsigned int max_buf_size = 200;
    for (int i = 0; i * max_buf_size < size; i++) {
      int min = size;
      if (max_buf_size < size)
        min = max_buf_size;
      putbuf(buffer + i * max_buf_size, min);
    }
    lock_release(&global_file_lock);
    return size;
  }
  struct file* my_file = process_current()->fd_table[fd];
  int num_wrote = file_write(my_file, buffer, size);
  lock_release(&global_file_lock);
  if (num_wrote < 0) {
    return 0;
  }
  return num_wrote;
}

void seek(int fd, unsigned position) {
  lock_acquire(&global_file_lock);
  if (!valid_fd(fd)) { // don't know if we can seek on stdout or not
    lock_release(&global_file_lock);
    return;
  }
  struct file* file = process_current()->fd_table[fd];
  file_seek(file, position);
  lock_release(&global_file_lock);
}

unsigned tell(int fd) {
  lock_acquire(&global_file_lock);
  if (!valid_fd(fd)) { // don't know if we can seek on stdout or not
    lock_release(&global_file_lock);
    return -1;
  }
  struct file* my_file = process_current()->fd_table[fd];
  off_t ret = file_tell(my_file);
  lock_release(&global_file_lock);
  return ret;
}

void close(int fd) {
  lock_acquire(&global_file_lock);
  if (!valid_fd(fd)) { // don't know if we can seek on stdout or not
    lock_release(&global_file_lock);
    // return -1;
  } else {
    struct file* file = process_current()->fd_table[fd];
    file_close(file);
    process_current()->fd_table[fd] = NULL;
    lock_release(&global_file_lock);
  }
}


double compute_e (int n) {
  if (n < 0) {
    return -1;
  }
  return sys_sum_to_e(n);
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
    //lock in the function
    f->eax = write(fd, buffer, size);
  } else if (args[0] == SYS_COMPUTE_E) {
    f->eax = compute_e(args[1]);
  }
}
