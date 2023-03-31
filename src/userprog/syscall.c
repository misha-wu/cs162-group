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
  struct thread* t = thread_current();
  struct process* p = t->pcb;
  // p->terminated = true;

  printf("%s: exit(%d)\n", p->process_name, status);
  exit_helper(status);
  return status;
}

// create syscall
int create(char* filename, unsigned initial_size) {
  lock_acquire(&global_file_lock);
  if (filename == NULL) {
    lock_release(&global_file_lock);
    exit(-1);
  // check conditions and try to create, which will return false if failed 
  } else if (strlen(filename) > 256 || !filesys_create(filename, initial_size)) {
    lock_release(&global_file_lock);
    return 0;
  } else {
    lock_release(&global_file_lock);
    return 1;
  }
  return 1;
}

// open syscall
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
  // add file to fd table and increment next available fd
  int fd = p->fd_index;
  p->fd_table[fd] = file;
  p->fd_index++;
  lock_release(&global_file_lock);
  return fd;
}

// remove syscall
bool remove (const char *file) {
  lock_acquire(&global_file_lock);
  if (file == NULL) {
    lock_release(&global_file_lock);
    return NULL;
  }
  lock_release(&global_file_lock);
  return filesys_remove(file);
}

// filesize syscall
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

// read syscall
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
    lock_release(&global_file_lock);
    return num_read;
  }
  // read from a file that is not stdin by calling the appropriate function
  struct file* file = process_current()->fd_table[fd];
  num_read = file_read(file, buffer, size);
  lock_release(&global_file_lock);
  return num_read;
}

// write syscall
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
    lock_release(&global_file_lock);
    return size;
  }
  // write to a file that is not stdout by calling the appropriate function
  struct file* my_file = process_current()->fd_table[fd];
  int num_wrote = file_write(my_file, buffer, size);
  lock_release(&global_file_lock);
  if (num_wrote < 0) {
    return 0;
  }
  return num_wrote;
}

// seek syscall
void seek(int fd, unsigned position) {
  lock_acquire(&global_file_lock);
  if (!valid_fd(fd)) {
    lock_release(&global_file_lock);
    return;
  }
  struct file* file = process_current()->fd_table[fd];
  file_seek(file, position);
  lock_release(&global_file_lock);
}

// tell syscall
unsigned tell(int fd) {
  lock_acquire(&global_file_lock);
  if (!valid_fd(fd)) {
    lock_release(&global_file_lock);
    return -1;
  }
  struct file* my_file = process_current()->fd_table[fd];
  off_t ret = file_tell(my_file);
  lock_release(&global_file_lock);
  return ret;
}

// close syscall
void close(int fd) {
  lock_acquire(&global_file_lock);
  if (!valid_fd(fd)) {
    lock_release(&global_file_lock);
  } else {
    struct file* file = process_current()->fd_table[fd];
    file_close(file);
    // mark that a fd has been closed by setting it to null
    process_current()->fd_table[fd] = NULL;
    lock_release(&global_file_lock);
  }
}

// compute_e syscall
double compute_e (int n) {
  if (n < 0) {
    return -1;
  }
  return sys_sum_to_e(n);
}

// typedef char lock_t;
// typedef char sema_t;

// bool lock_init_sys(lock_t* lock) {
//   if (lock == NULL) {
    
//   }
//   struct WO_DE_LOCK* mylock = malloc(sizeof(struct WO_DE_LOCK));
//   struct process* p = process_current();
//   lock_acquire(&p->lock_counter_lock);
//   *lock = p->lock_counter;
//   p->lock_counter++;
//   lock_release(&p->lock_counter_lock);
//   mylock->user_lock = *lock;
//   lock_init(&mylock->kernel_lock);
//   list_push_back(&p->user_lock_list, &mylock->lock_elem);
// }

bool lock_init_sys(lock_t* lock) {
  // if (*lock == NULL) {
  if (lock == NULL) {
    return false;
  }
  struct WO_DE_LOCK* mylock = malloc(sizeof(struct WO_DE_LOCK));
  struct process* p = process_current();
  lock_acquire(&p->lock_counter_lock);
  *lock = p->lock_counter;
  p->lock_counter++;
  lock_release(&p->lock_counter_lock);
  mylock->user_lock = *lock;
  lock_init(&mylock->kernel_lock);
  enum intr_level old_level;
  old_level = intr_disable();
  list_push_back(&p->user_lock_list, &mylock->lock_elem);
  intr_set_level(old_level);
  return true;
}

WO_DE_LOCK_t* get_wrapper_from_lock(lock_t* lock) {
  if (lock == NULL) { // ??? dereference
    return NULL;
  }
  WO_DE_LOCK_t* my_lock = NULL;
  struct list_elem* e;
  struct thread* t = thread_current();
  struct process* p = t->pcb;

  for (e = list_begin(&p->user_lock_list); e != list_end(&p->user_lock_list); e = list_next(e)) {
    WO_DE_LOCK_t* l = list_entry(e, struct WO_DE_LOCK, lock_elem);
    if (l->user_lock == *lock) {
      my_lock = l;
      break;
    }
  }
  return my_lock;
}


WO_DE_SEMA_t* get_wrapper_from_sema(sema_t* sema) {
  if (sema == NULL)
    return NULL;
  WO_DE_SEMA_t* my_sema = NULL;
  struct list_elem* e;
  struct thread* t = thread_current();
  struct process* p = t->pcb;

  for (e = list_begin(&p->user_sema_list); e != list_end(&p->user_sema_list); e = list_next(e)) {
    WO_DE_SEMA_t* s = list_entry(e, struct WO_DE_SEMA, sema_elem);
    if (s->user_sema == *sema) {
      my_sema = s;
      break;
    }
  }
  return my_sema;
}

bool lock_acquire_sys(lock_t* lock) {
  WO_DE_LOCK_t* my_lock = get_wrapper_from_lock(lock);
  enum intr_level old_level;
  old_level = intr_disable();
  if(my_lock == NULL) {
    intr_set_level(old_level);
    return false;
  }
  if(lock_held_by_current_thread(&(my_lock->kernel_lock))) {
    intr_set_level(old_level);
    return false;
  }
  lock_acquire(&(my_lock->kernel_lock));
  intr_set_level(old_level);
  return true;
}

bool lock_release_sys(lock_t* lock) {
  WO_DE_LOCK_t* my_lock = get_wrapper_from_lock(lock);
  enum intr_level old_level;
  old_level = intr_disable();
  if(my_lock == NULL) {
    intr_set_level(old_level);
    return false;
  }
  if(!lock_held_by_current_thread(&(my_lock->kernel_lock))) {
    intr_set_level(old_level);
    return false;
  }
  lock_release(&(my_lock->kernel_lock));
  intr_set_level(old_level);
  return true;
}


bool sema_init_sys(sema_t* sema, int val) {

  // if (lock == NULL) {
  //   return false;
  // }
  // struct WO_DE_LOCK* mylock = malloc(sizeof(struct WO_DE_LOCK));
  // struct process* p = process_current();
  // lock_acquire(&p->lock_counter_lock);
  // *lock = p->lock_counter;
  // p->lock_counter++;
  // lock_release(&p->lock_counter_lock);
  // mylock->user_lock = *lock;
  // lock_init(&mylock->kernel_lock);
  // list_push_back(&p->user_lock_list, &mylock->lock_elem);
  // return true;


  //input validation
  if (sema == NULL || val < 0) //check valid sema pointer, valid value
    return false;
  struct WO_DE_SEMA* my_sema = malloc(sizeof(struct WO_DE_SEMA));
  struct process* p = process_current();
  lock_acquire(&p->sema_counter_lock);
  // acquire sema_counter_lock
  *sema = p->sema_counter;
  p->sema_counter++;
  lock_release(&p->sema_counter_lock);
  // release sema_counter_lock
  // WO_DE_SEMA_t* my_sema = malloc()
  my_sema->value = val;
  my_sema->user_sema = *sema;
  sema_init(&my_sema->kernel_sema, val);
  enum intr_level old_level;
  old_level = intr_disable();
  list_push_back(&p->user_sema_list, &my_sema->sema_elem);
  intr_set_level(old_level);
  return true;
}


bool sema_down_sys(sema_t* sema) {
  // WO_DE_LOCK_t* my_lock = get_wrapper_from_lock(lock);
  // enum intr_level old_level;
  // old_level = intr_disable();
  // if(my_lock == NULL) {
  //   intr_set_level(old_level);
  //   return false;
  // }
  // if(lock_held_by_current_thread(&(my_lock->kernel_lock))) {
  //   intr_set_level(old_level);
  //   return false;
  // }
  // lock_acquire(&(my_lock->kernel_lock));
  // intr_set_level(old_level);
  // return true;

  WO_DE_SEMA_t* my_sema = get_wrapper_from_sema(sema);
  enum intr_level old_level;
  old_level = intr_disable();
  if (my_sema == NULL) {
    intr_set_level(old_level);
    return false;
  }
  sema_down(&my_sema->kernel_sema);
  intr_set_level(old_level);
  return true;
}


bool sema_up_sys(sema_t* sema) {
  WO_DE_SEMA_t* my_sema = get_wrapper_from_sema(sema);
  enum intr_level old_level;
  old_level = intr_disable();
  if (my_sema == NULL) {
    intr_set_level(old_level);
    return false;
  }
  sema_up(&my_sema->kernel_sema);
  intr_set_level(old_level);
  return true;
}

// USER THREADS
tid_t sys_pthread_create(stub_fun sfun, pthread_fun tfun, const void* arg) {
  return pthread_execute_funsies(sfun, tfun, arg);
}

void sys_pthread_exit(void) {
  pthread_exit();
}

tid_t sys_pthread_join(tid_t tid) {
  return pthread_join(tid);
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
  } else if (args[0] == SYS_LOCK_INIT) {
    f->eax = lock_init_sys(args[1]);
  } else if (args[0] == SYS_LOCK_ACQUIRE) {
    f->eax = lock_acquire_sys(args[1]);
  } else if (args[0] == SYS_LOCK_RELEASE) {
    f->eax = lock_release_sys(args[1]);
  } else if (args[0] == SYS_SEMA_INIT) {
    f->eax = sema_init_sys(args[1], args[2]);
  } else if (args[0] == SYS_SEMA_DOWN) {
    f->eax = sema_down_sys(args[1]);
  } else if (args[0] == SYS_SEMA_UP) {
    f->eax = sema_up_sys(args[1]);
  } else if (args[0] == SYS_PT_CREATE) {
    f->eax = sys_pthread_create(args[1], args[2], args[3]);
  } else if (args[0] == SYS_PT_EXIT) {
    sys_pthread_exit();
  } else if (args[0] == SYS_PT_JOIN) {
    f->eax = sys_pthread_join(args[1]);
  }
}
