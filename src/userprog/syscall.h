#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "lib/stdbool.h"
#include <stdint.h>
#include "threads/synch.h"

// slightly sus 0.0
typedef char lock_t;
typedef char sema_t;

typedef struct WO_DE_LOCK {
  struct lock kernel_lock; //kernel version
  lock_t user_lock; //user lock
  struct list_elem lock_elem;

  // struct lock mutex_lock;
} WO_DE_LOCK_t;

typedef struct WO_DE_SEMA {
  struct semaphore kernel_sema; //kernel version
  sema_t user_sema; //user lock
  int value;
  struct list_elem sema_elem;
  // struct lock mutex_lock;
} WO_DE_SEMA_t;

// typedef struct WO_DE_LOCK {
//   struct lock kernel_lock; //kernel version
//   struct lock user_lock; //user lock
//   struct list_elem lock_elem;

//   struct lock mutex_lock;
// } WO_DE_LOCK_t;

// typedef struct WO_DE_SEMA {
//   struct semaphore kernel_sema; //kernel version
//   struct semaphore user_sema; //user lock
//   int value;
//   struct list_elem sema_elem;
//   struct lock mutex_lock;
// } WO_DE_SEMA_t;

void syscall_init(void);

/* Utility functions */
bool valid_fd(int fd);
bool valid_address(void* address);
void exit_helper(int exit_code);
struct process* process_current(void);

/* Helper functions*/
int exit(int status);
int create(char* filename, unsigned initial_size);
int open (char *name);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
double compute_e (int n);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
bool remove (const char *file);

#endif /* userprog/syscall.h */