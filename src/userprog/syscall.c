#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

struct lock global_file_lock;

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { 
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); 
  lock_init(&global_file_lock);
  }

int exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
  exit_helper();
  return status;
}

int create(char* filename, unsigned initial_size) {
  lock_acquire(&global_file_lock);
  if (filename == NULL) {
    lock_release(&global_file_lock);
    exit(-1);
  } else if (initial_size > 256 || strlen(filename) > 256 || !filesys_create(filename, initial_size)) {
    lock_release(&global_file_lock);
    return 0;
  } else {
    lock_release(&global_file_lock);
    return 1;
  }
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
  struct thread* t = thread_current();
  struct process* p = t->pcb;
  int fd = p->fd_index;
  p->fd_table[fd] = file;
  p->fd_index++;
  lock_release(&global_file_lock);
  return fd;
}

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
    // TODO: implement argument validation
    // STARTER CODE
    // f->eax = args[1];
    // printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    // process_exit();
    // END STARTER CODE
    f->eax = exit(args[1]);
    
    // TODO: maybe free file descriptor table (FDT)
    // TODO: loop through children and decrease refcnt
  } else if (args[0] == SYS_PRACTICE) {
    f->eax = args[1] + 1;
  } else if (args[0] == SYS_HALT) {
    shutdown_power_off();
  } else if (args[0] == SYS_EXEC) {
    process_exec(args[1]);
  } else if (args[0] == SYS_CREATE) {
    char* filename = (char*) args[1];
    unsigned initial_size = (unsigned) args[2];
    f->eax = create(filename, initial_size);
  } else if (args[0] == SYS_OPEN) {
    char* name = (char*) args[1];
    f->eax = open(name);
  } else if (args[0] == SYS_WRITE) {
    int fd = args[1];
    char* buffer = (char *) args[2];
    unsigned size = (unsigned) args[3];
    if (fd == 1) {
      // change if needed? we don't know how big a few hundred is :')
      int max_buf_size = 200;
      for (int i = 0; i * max_buf_size < size; i++) {
        int min = size;
        if (max_buf_size < size)
          min = max_buf_size;
        putbuf(buffer + i * max_buf_size, min);
      }
      return size;
    }
    // TODO: implement for not standard out
  }
}
