#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127


/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */

  // WOMENDECODE WODE OUR CODE OUR CHENGXU
  struct process_status* my_own; // stores the current process's process_status
  struct list children; // pintos list of children's process_status

  struct file* fd_table[256];
  int fd_index;
  int magic;
};

typedef struct process_status { 
  struct semaphore sema; // for scheduling; initialize to 0 
  struct lock lock; // for ref_count updates
  int ref_cnt; // initialized to 2 b/c 2 processes (the own process and its parent) care about its status
  pid_t pid; // which process
  int exit_code; // exit code of process 
  bool load_success; // stores whether the child successfully loaded
  struct list_elem elem;
  bool waited_on;
} process_status_t;

struct start_process_arg {
  process_status_t* child_status;
  char* file_name;
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif 