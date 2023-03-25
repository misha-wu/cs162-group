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
  uint32_t* pagedir;              /* Page directory. */
  char process_name[16];          /* Name of the main thread */
  struct thread* main_thread;     /* Pointer to main thread */
  struct process_status* my_own;  /* Stores the current process's process_status */
  struct list children;           /* Pintos list of children's process_status */
  struct file* fd_table[256];     /* Array of file* storing mappings from file descriptors to files */
  int fd_index;                   /* The next available file descriptor */


  struct list user_lock_list; //list of WO_DE_LOCK_t*
  struct list user_sema_list; //list of WO_DE_SEMA_t*
  int lock_counter; // keeps track of how many locks have been created so far, init to 0
  int sema_counter; // keeps track of how many semas have been created so far, init to 0
  struct lock lock_counter_lock; // lock lock_counter from being modified by multiple threads simulateanously
  struct lock sema_counter_lock; // lock sema_counter from being modified by multiple threads simulateanously
};

typedef struct process_status { 
  struct semaphore sema;          /* For scheduling; initialize to 0 */
  struct lock lock;               /* For ref_count updates */
  int ref_cnt;                    /* Initialized to 2 because 2 processes (the own process and its parent) care about its status */
  pid_t pid;                      /* PID of process */
  int exit_code;                  /* Exit code of process */
  bool load_success;              /* Stores whether the child successfully loaded */
  struct list_elem elem;          /* list_elem so that we can put process_status in a Pintos list */
} process_status_t;

struct start_process_arg {        /* Struct to pass in as an argument to start_process, */
  process_status_t* child_status; /* so that we are able to pass in our process_status in addition to the file_name */
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