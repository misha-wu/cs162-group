#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "lib/stdbool.h"
#include <stdint.h>

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
