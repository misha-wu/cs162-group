// #include "userprog/process.h"
// #include <debug.h>
// #include <inttypes.h>
// #include <round.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include "userprog/gdt.h"
// #include "userprog/pagedir.h"
// #include "userprog/tss.h"
// #include "filesys/directory.h"
// #include "filesys/file.h"
// #include "filesys/filesys.h"
// #include "threads/flags.h"
// #include "threads/init.h"
// #include "threads/interrupt.h"
// #include "threads/malloc.h"
// #include "threads/palloc.h"
// #include "threads/synch.h"
// #include "threads/thread.h"
// #include "threads/vaddr.h"

// #include "userprog/syscall.h"

// static thread_func start_process NO_RETURN;
// static thread_func start_pthread NO_RETURN;
// static bool load(const char* file_name, void (**eip)(void), void** esp);
// bool setup_thread(void (**eip)(void), void** esp);

// /* Initializes user programs in the system by ensuring the main
//    thread has a minimal PCB so that it can execute and wait for
//    the first user process. Any additions to the PCB should be also
//    initialized here if main needs those members */
// void userprog_init(void) {
//   struct thread* t = thread_current();
//   bool success;

//   /* Allocate process control block
//      It is imoprtant that this is a call to calloc and not malloc,
//      so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
//      page directory) when t->pcb is assigned, because a timer interrupt
//      can come at any time and activate our pagedir */
//   t->pcb = calloc(sizeof(struct process), 1);
//   success = t->pcb != NULL;

//   /* Kill the kernel if we did not succeed */
//   ASSERT(success);

//   list_init(&(t->pcb->children));
// }

// /* Starts a new thread running a user program loaded from
//    FILENAME.  The new thread may be scheduled (and may even exit)
//    before process_execute() returns.  Returns the new process's
//    process id, or TID_ERROR if the thread cannot be created. */
// pid_t process_execute(const char* file_name) {
//   char* fn_copy;
//   tid_t tid;

//   /* Make a copy of FILE_NAME.
//      Otherwise there's a race between the caller and load(). */
//   fn_copy = palloc_get_page(0);
//   if (fn_copy == NULL)
//     return -1;
//   strlcpy(fn_copy, file_name, PGSIZE);

//   struct process_status* child_status = palloc_get_page(0);
//   if (child_status == NULL) {
//     palloc_free_page(fn_copy);
//     return -1; 
//   }

//   // initializes the child's process_status
//   lock_init(&(child_status->lock));
//   sema_init(&(child_status->sema), 0);
//   child_status->ref_cnt = 2; 

//   // struct to pass in as an argument to start_process, since it only takes one void* argument
//   struct start_process_arg* arg = palloc_get_page(0);
//   if (arg == NULL) {
//     palloc_free_page(fn_copy);
//     palloc_free_page(child_status);
//     return -1; 
//   }
//   arg -> file_name = fn_copy;
//   arg -> child_status = child_status;

//   /* Create a new thread to execute FILE_NAME. */
//   tid = thread_create(file_name, PRI_DEFAULT, start_process, arg);
//   sema_down(&(child_status->sema));
//   if (tid == TID_ERROR) {
//     palloc_free_page(fn_copy);
//     palloc_free_page(child_status);
//     palloc_free_page(arg);
//   }
//   if (tid == TID_ERROR || !child_status->load_success) {
//     return -1; 
//   }
//   child_status->pid = tid;

//   struct thread* cur = thread_current();
//   struct process* p = cur->pcb;
//   // add child's process_status to our list of children
//   list_push_back(&(p->children), &child_status->elem);
//   return tid;
// }

// /* A thread function that loads a user process and starts it
//    running. */
// static void start_process(void* sp_arg) {
//   struct start_process_arg* arg = (struct start_process_arg*) sp_arg;
//   char* file_name = arg->file_name;
//   struct process_status* p_status = arg->child_status;
//   struct thread* t = thread_current();
//   struct intr_frame if_;
//   bool success, pcb_success;

//   /* Allocate process control block */
//   struct process* new_pcb = malloc(sizeof(struct process));
//   success = pcb_success = new_pcb != NULL;
  
//   /* Initialize process control block */
//   if (success) {
//     new_pcb->my_own = p_status;
//     list_init(&(new_pcb->children));

//     // Ensure that timer_interrupt() -> schedule() -> process_activate()
//     // does not try to activate our uninitialized pagedir
//     new_pcb->pagedir = NULL;
//     t->pcb = new_pcb;

//     // Continue initializing the PCB as normal
//     t->pcb->main_thread = t;
//     strlcpy(t->pcb->process_name, t->name, sizeof t->name);

//     // our first available file descriptor is 3 because 0, 1, and 2 are reserved for stdin, stdout, stderr
//     new_pcb->fd_index = 3;
//     // set mappings of 0, 1, and 2 to null because they don't correspond to acutal files
//     new_pcb->fd_table[0] = NULL;
//     new_pcb->fd_table[1] = NULL;
//     new_pcb->fd_table[2] = NULL;

//     // USER THREADS initialization

//     list_init(&(new_pcb->threads_list));
//     list_init(&(new_pcb->join_list));
//     list_init(&(new_pcb->user_sema_list));
//     list_init(&(new_pcb->user_lock_list));
//     new_pcb->lock_counter = 0;
//     new_pcb->sema_counter = 0;

//     lock_init(&new_pcb->threads_list_lock);
//     lock_init(&new_pcb->join_list_lock);

//     lock_init(&new_pcb->lock_counter_lock);
//     lock_init(&new_pcb->sema_counter_lock);


//     struct join_struct* sema_and_thread = palloc_get_page(0);

//     if (sema_and_thread == NULL) {
//       printf("we have problems!!! in sema nad thread");
//       // what do we do here??? TODO maybe multimoo
//       // palloc_free_page(sparg);
//       return TID_ERROR;
//     }

//     sema_and_thread->tid = t->tid;
//     sema_init(&(sema_and_thread->join_sema), 1);

//     lock_acquire(&(new_pcb->join_list_lock));
//     list_push_back(&(new_pcb->join_list), &(sema_and_thread->elem));
//     lock_release(&(new_pcb->join_list_lock));

//     lock_acquire(&(new_pcb->threads_list_lock));
//     list_push_back(&(new_pcb->threads_list), &(t->im_a_thread_elem));
//     lock_release(&(new_pcb->threads_list_lock));

//     // calloc remaining structs? or not
//   }

//   /* Initialize interrupt frame and load executable. */
//   if (success) {
//     memset(&if_, 0, sizeof if_);
//     if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
//     if_.cs = SEL_UCSEG;
//     if_.eflags = FLAG_IF | FLAG_MBS;

//     /* save our existing FPU of the current process in a temporary local 27-int array variable, 
//     initialize the FPU with fninit, save the contents of the FPU into the intr_frame struct, 
//     then restore the contents of our FPU from the temporary variable */
//     uint32_t tempfpu[27];
//     asm volatile ("fsave (%0); fninit; fsave (%1); frstor (%0)" : : "g"(&tempfpu), "g"(&if_.fpu));
//     success = load(file_name, &if_.eip, &if_.esp);
//   }

//   p_status->load_success = success;
//   sema_up(&(p_status->sema));

//   /* Handle failure with succesful PCB malloc. Must free the PCB */
//   if (!success && pcb_success) {
//     // Avoid race where PCB is freed before t->pcb is set to NULL
//     // If this happens, then an unfortuantely timed timer interrupt
//     // can try to activate the pagedir, but it is now freed memory
//     struct process* pcb_to_free = t->pcb;
//     t->pcb = NULL;
//     free(pcb_to_free);
//   }

//   /* Clean up. Exit on failure or jump to userspace */
//   palloc_free_page(file_name);
//   palloc_free_page(sp_arg);
//   if (!success) {
//     palloc_free_page(p_status);
//     thread_exit();
//   }

//   /* Start the user process by simulating a return from an
//      interrupt, implemented by intr_exit (in
//      threads/intr-stubs.S).  Because intr_exit takes all of its
//      arguments on the stack in the form of a `struct intr_frame',
//      we just point the stack pointer (%esp) to our stack frame
//      and jump to it. */
//   asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
//   NOT_REACHED();
// }

// /* Waits for process with PID child_pid to die and returns its exit status.
//    If it was terminated by the kernel (i.e. killed due to an
//    exception), returns -1.  If child_pid is invalid or if it was not a
//    child of the calling process, or if process_wait() has already
//    been successfully called for the given PID, returns -1
//    immediately, without waiting.

//    This function will be implemented in problem 2-2.  For now, it
//    does nothing. */
// int process_wait(pid_t child_pid UNUSED) {
//   struct thread* cur = thread_current();
//   struct process* p = cur->pcb;
//   struct list_elem* e;
//   struct process_status* child_status = NULL;

//   // iterate through our list of children
//   for (e = list_begin(&p->children); e != list_end(&p->children); e = list_next(e)) {
//     struct process_status* p_status = list_entry(e, struct process_status, elem);
//     // check if we find a match
//     if (p_status->pid == child_pid) {
//       child_status = p_status;
//       break;
//     }
//   }

//   if (child_status == NULL) {
//     return -1;
//   }

//   sema_down(&child_status->sema);
//   int exit_code = child_status->exit_code;
  
//   decrement_and_mayhap_free(child_status);
//   return exit_code;
// }

// // decrements the reference count of the given process_status and checks if it is at 0 so that we can free it and remove it from parent's list
// void decrement_and_mayhap_free(struct process_status* p_status) {
//   lock_acquire(&(p_status->lock));
//   int ref_cnt = -- p_status-> ref_cnt;
//   lock_release(&(p_status->lock));
//   if (ref_cnt == 0) {
//     list_remove(&p_status->elem);
//     palloc_free_page(p_status);
//   }
// }

// // lets us take care of the exit code before calling process_exit
// void exit_helper(int exit_code) {
//   struct thread* cur = thread_current();
//   process_status_t* mine = cur->pcb->my_own;
//   mine->exit_code = exit_code;
//   process_exit();
// }

// /* Free the current process's resources. */
// void process_exit(void) {
//   struct thread* cur = thread_current();
//   uint32_t* pd;

//   /* If this thread does not have a PCB, don't worry */
//   if (cur->pcb == NULL) {
//     thread_exit();
//     NOT_REACHED();
//   }

//   process_status_t* mine = cur->pcb->my_own;

//   sema_up(&(mine->sema));
//   decrement_and_mayhap_free(mine);

//   struct process* p = cur->pcb;
//   struct list_elem* e;
  
//   // iterate through list of children and decrement ref_cnt/check if they can be freed
//   for (e = list_begin(&p->children); e != list_end(&p->children);) {
//     struct process_status* p_status = list_entry(e, struct process_status, elem);
//     struct list_elem* next = list_next(e);
//     decrement_and_mayhap_free(p_status);
//     e = next;
//   }

//     // TODO: free the join struct list
//   for (e = list_begin(&p->join_list); e != list_end(&p->join_list);) {
//     struct join_struct* js = list_entry(e, struct join_struct, elem);
//     struct list_elem* next = list_next(e);
//     palloc_free_page(js);
//     e = next;
//   }

//   // for (e = list_begin(&p->threads_list); e != list_end(&p->threads_list);) {
//   //   struct thread* t = list_entry(e, struct thread, im_a_thread_elem);
//   //   struct list_elem* next = list_next(e);
//   //   palloc_free_page(js);
//   //   e = next;
//   // }

//   // free all the locks
//   for (e = list_begin(&p->user_lock_list); e != list_end(&p->user_lock_list);) {
//     struct WO_DE_LOCK* l = list_entry(e, struct WO_DE_LOCK, lock_elem);
//     struct list_elem* next = list_next(e);
//     if (lock_held_by_current_thread(&(l->kernel_lock))){
//       lock_release(&(l->kernel_lock));
//     } 
//     free(l);
//     e = next;
//   }

//   for (e = list_begin(&p->user_sema_list); e != list_end(&p->user_sema_list);) {
//     struct WO_DE_SEMA* s = list_entry(e, struct WO_DE_SEMA, sema_elem);
//     struct list_elem* next = list_next(e);
//     // if (lock_held_by_current_thread(&(l->kernel_lock))){
//     //   lock_release(&(l->kernel_lock));
//     // } 
//     free(s);
//     e = next;
//   }


//   // close file descriptors
//   for (int i = 0; i < 256; i++) {
//     if (p->fd_table[i] != NULL) {
//       close(i);
//     }
//   }

//   // TODO: free the join struct list

//   /* Destroy the current process's page directory and switch back
//      to the kernel-only page directory. */
//   pd = cur->pcb->pagedir;
//   if (pd != NULL) {
//     /* Correct ordering here is crucial.  We must set
//          cur->pcb->pagedir to NULL before switching page directories,
//          so that a timer interrupt can't switch back to the
//          process page directory.  We must activate the base page
//          directory before destroying the process's page
//          directory, or our active page directory will be one
//          that's been freed (and cleared). */
//     cur->pcb->pagedir = NULL;
//     pagedir_activate(NULL);
//     pagedir_destroy(pd);
//   }

//   /* Free the PCB of this process and kill this thread
//      Avoid race where PCB is freed before t->pcb is set to NULL
//      If this happens, then an unfortuantely timed timer interrupt
//      can try to activate the pagedir, but it is now freed memory */
//   struct process* pcb_to_free = cur->pcb;
//   cur->pcb = NULL;
//   free(pcb_to_free);

//   thread_exit();
// }

// /* Sets up the CPU for running user code in the current
//    thread. This function is called on every context switch. */
// void process_activate(void) {
//   struct thread* t = thread_current();

//   /* Activate thread's page tables. */
//   if (t->pcb != NULL && t->pcb->pagedir != NULL)
//     pagedir_activate(t->pcb->pagedir);
//   else
//     pagedir_activate(NULL);

//   /* Set thread's kernel stack for use in processing interrupts.
//      This does nothing if this is not a user process. */
//   tss_update();
// }

// /* We load ELF binaries.  The following definitions are taken
//    from the ELF specification, [ELF1], more-or-less verbatim.  */

// /* ELF types.  See [ELF1] 1-2. */
// typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
// typedef uint16_t Elf32_Half;

// /* For use with ELF types in printf(). */
// #define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
// #define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
// #define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
// #define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

// /* Executable header.  See [ELF1] 1-4 to 1-8.
//    This appears at the very beginning of an ELF binary. */
// struct Elf32_Ehdr {
//   unsigned char e_ident[16];
//   Elf32_Half e_type;
//   Elf32_Half e_machine;
//   Elf32_Word e_version;
//   Elf32_Addr e_entry;
//   Elf32_Off e_phoff;
//   Elf32_Off e_shoff;
//   Elf32_Word e_flags;
//   Elf32_Half e_ehsize;
//   Elf32_Half e_phentsize;
//   Elf32_Half e_phnum;
//   Elf32_Half e_shentsize;
//   Elf32_Half e_shnum;
//   Elf32_Half e_shstrndx;
// };

// /* Program header.  See [ELF1] 2-2 to 2-4.
//    There are e_phnum of these, starting at file offset e_phoff
//    (see [ELF1] 1-6). */
// struct Elf32_Phdr {
//   Elf32_Word p_type;
//   Elf32_Off p_offset;
//   Elf32_Addr p_vaddr;
//   Elf32_Addr p_paddr;
//   Elf32_Word p_filesz;
//   Elf32_Word p_memsz;
//   Elf32_Word p_flags;
//   Elf32_Word p_align;
// };

// /* Values for p_type.  See [ELF1] 2-3. */
// #define PT_NULL 0           /* Ignore. */
// #define PT_LOAD 1           /* Loadable segment. */
// #define PT_DYNAMIC 2        /* Dynamic linking info. */
// #define PT_INTERP 3         /* Name of dynamic loader. */
// #define PT_NOTE 4           /* Auxiliary info. */
// #define PT_SHLIB 5          /* Reserved. */
// #define PT_PHDR 6           /* Program header table. */
// #define PT_STACK 0x6474e551 /* Stack segment. */

// /* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
// #define PF_X 1 /* Executable. */
// #define PF_W 2 /* Writable. */
// #define PF_R 4 /* Readable. */

// static bool setup_stack(void** esp, int argc, char* argv[]);
// static bool validate_segment(const struct Elf32_Phdr*, struct file*);
// static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
//                          uint32_t zero_bytes, bool writable);

// /* Loads an ELF executable from FILE_NAME into the current thread.
//    Stores the executable's entry point into *EIP
//    and its initial stack pointer into *ESP.
//    Returns true if successful, false otherwise. */
// bool load(const char* file_name, void (**eip)(void), void** esp) {
//   char* save;
//   char* token = strtok_r(file_name, " ", &save);
//   int argc = 0;
//   char* long_argv[100];
//   while (token != NULL) {
//     long_argv[argc] = token;
//     argc++;
//     token = strtok_r(NULL, " ", &save);
//   }

//   char* argv[argc];
//   for (int i = 0; i < argc; i++) {
//     argv[i] = long_argv[i];
//   }


//   struct thread* t = thread_current();
//   struct Elf32_Ehdr ehdr;
//   struct file* file = NULL;
//   off_t file_ofs;
//   bool success = false;
//   int i;

//   strlcpy(t->pcb->process_name, argv[0], strlen(argv[0]) + 1);

//   /* Allocate and activate page directory. */
//   t->pcb->pagedir = pagedir_create();
//   if (t->pcb->pagedir == NULL)
//     goto done;
//   process_activate();

//   /* Open executable file. */
//   file = filesys_open(file_name);
  
//   if (file == NULL) {
//     printf("load: %s: open failed\n", file_name);
//     goto done;
//   }
//   file_deny_write(file);

//   /* Read and verify executable header. */
//   if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
//       memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
//       ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
//     printf("load: %s: error loading executable\n", file_name);
//     goto done;
//   }

//   /* Read program headers. */
//   file_ofs = ehdr.e_phoff;
//   for (i = 0; i < ehdr.e_phnum; i++) {
//     struct Elf32_Phdr phdr;

//     if (file_ofs < 0 || file_ofs > file_length(file))
//       goto done;
//     file_seek(file, file_ofs);

//     if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
//       goto done;
//     file_ofs += sizeof phdr;
//     switch (phdr.p_type) {
//       case PT_NULL:
//       case PT_NOTE:
//       case PT_PHDR:
//       case PT_STACK:
//       default:
//         /* Ignore this segment. */
//         break;
//       case PT_DYNAMIC:
//       case PT_INTERP:
//       case PT_SHLIB:
//         goto done;
//       case PT_LOAD:
//         if (validate_segment(&phdr, file)) {
//           bool writable = (phdr.p_flags & PF_W) != 0;
//           uint32_t file_page = phdr.p_offset & ~PGMASK;
//           uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
//           uint32_t page_offset = phdr.p_vaddr & PGMASK;
//           uint32_t read_bytes, zero_bytes;
//           if (phdr.p_filesz > 0) {
//             /* Normal segment.
//                      Read initial part from disk and zero the rest. */
//             read_bytes = page_offset + phdr.p_filesz;
//             zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
//           } else {
//             /* Entirely zero.
//                      Don't read anything from disk. */
//             read_bytes = 0;
//             zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
//           }
//           if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
//             goto done;
//         } else
//           goto done;
//         break;
//     }
//   }

//   /* Set up stack. */
//   if (!setup_stack(esp, argc, argv))
//     goto done;

//   /* Start address. */
//   *eip = (void (*)(void))ehdr.e_entry;

//   success = true;

// done:
//   /* We arrive here whether the load is successful or not. */
//   file_close(file);
//   return success;
// }

// /* load() helpers. */

// static bool install_page(void* upage, void* kpage, bool writable);

// /* Checks whether PHDR describes a valid, loadable segment in
//    FILE and returns true if so, false otherwise. */
// static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
//   /* p_offset and p_vaddr must have the same page offset. */
//   if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
//     return false;

//   /* p_offset must point within FILE. */
//   if (phdr->p_offset > (Elf32_Off)file_length(file))
//     return false;

//   /* p_memsz must be at least as big as p_filesz. */
//   if (phdr->p_memsz < phdr->p_filesz)
//     return false;

//   /* The segment must not be empty. */
//   if (phdr->p_memsz == 0)
//     return false;

//   /* The virtual memory region must both start and end within the
//      user address space range. */
//   if (!is_user_vaddr((void*)phdr->p_vaddr))
//     return false;
//   if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
//     return false;

//   /* The region cannot "wrap around" across the kernel virtual
//      address space. */
//   if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
//     return false;

//   /* Disallow mapping page 0.
//      Not only is it a bad idea to map page 0, but if we allowed
//      it then user code that passed a null pointer to system calls
//      could quite likely panic the kernel by way of null pointer
//      assertions in memcpy(), etc. */
//   if (phdr->p_vaddr < PGSIZE)
//     return false;

//   /* It's okay. */
//   return true;
// }

// /* Loads a segment starting at offset OFS in FILE at address
//    UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
//    memory are initialized, as follows:

//         - READ_BYTES bytes at UPAGE must be read from FILE
//           starting at offset OFS.

//         - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

//    The pages initialized by this function must be writable by the
//    user process if WRITABLE is true, read-only otherwise.

//    Return true if successful, false if a memory allocation error
//    or disk read error occurs. */
// static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
//                          uint32_t zero_bytes, bool writable) {
//   ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
//   ASSERT(pg_ofs(upage) == 0);
//   ASSERT(ofs % PGSIZE == 0);

//   file_seek(file, ofs);
//   while (read_bytes > 0 || zero_bytes > 0) {
//     /* Calculate how to fill this page.
//          We will read PAGE_READ_BYTES bytes from FILE
//          and zero the final PAGE_ZERO_BYTES bytes. */
//     size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
//     size_t page_zero_bytes = PGSIZE - page_read_bytes;

//     /* Get a page of memory. */
//     uint8_t* kpage = palloc_get_page(PAL_USER);
//     if (kpage == NULL)
//       return false;

//     /* Load this page. */
//     if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
//       palloc_free_page(kpage);
//       return false;
//     }
//     memset(kpage + page_read_bytes, 0, page_zero_bytes);

//     /* Add the page to the process's address space. */
//     if (!install_page(upage, kpage, writable)) {
//       palloc_free_page(kpage);
//       return false;
//     }

//     /* Advance. */
//     read_bytes -= page_read_bytes;
//     zero_bytes -= page_zero_bytes;
//     upage += PGSIZE;
//   }
//   return true;
// }

// /* Create a minimal stack by mapping a zeroed page at the top of
//    user virtual memory. */
// static bool setup_stack(void** esp_uncasted, int argc, char* argv[]) {
//   uint8_t* kpage;
//   bool success = false;

//   kpage = palloc_get_page(PAL_USER | PAL_ZERO);
//   if (kpage != NULL) {
//     success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
//     if (success) {
//       *esp_uncasted = PHYS_BASE;

//       // we need *esp to not be a void* so that we can dereference it
//       char** esp = (char **) esp_uncasted;

//       int32_t word_addresses[argc];
//       // iterate through the arguments. the following loop "put[s] the arguments for the initial function on the stack" (spec)
//       for (int i = 0; i < argc; i++) {
//         // need to decrement the stack pointer
//         *esp -= 1;

//         // add a null terminator for the string
//         **esp = '\0';

//         int len = strlen(argv[i]);
//         // iterate through each character to put it on the stack
//         for (int j = len - 1; j >= 0; j--) {
//           // decrement stack pointer
//           *esp -= 1;
//           // set memory at address of stack pointer to be this character
//           **esp = argv[i][j];
//         }

//         // save the address of this argument
//         word_addresses[i] = *esp;
//       }

//       int stored = PHYS_BASE - (int) *esp;
//       // calculate how many bytes we need to pad for stack alignment after the arguments are added
//       int aligned = 16 - ((stored + (argc + 1) * 4 + 8) % 16);
//       *esp -= aligned;
      
//       // puts null pointer sentinel onto the stack
//       *esp -= 4;
//       int32_t zero = 0;
//       **esp = zero;

//       // puts the addresses of each string onto the stack
//       for (int i = argc - 1; i >= 0; i--) {
//         *esp -= 4;
//         int** int_esp = (int**) esp;
//         **int_esp = word_addresses[i];
//       }

//       // puts argv on the stack
//       *esp -= 4;
//       int** int_esp = (int**) esp;
//       **int_esp = (int) *esp + 4;

//       // puts argc on the stack
//       *esp -= 4;
//       **esp = argc;

//       // puts "return address" on the stack
//       *esp -= 4;
//       **esp = 0;
      
//     } else {
//       palloc_free_page(kpage);
//     }
//   }
//   return success;
// }

// /* Adds a mapping from user virtual address UPAGE to kernel
//    virtual address KPAGE to the page table.
//    If WRITABLE is true, the user process may modify the page;
//    otherwise, it is read-only.
//    UPAGE must not already be mapped.
//    KPAGE should probably be a page obtained from the user pool
//    with palloc_get_page().
//    Returns true on success, false if UPAGE is already mapped or
//    if memory allocation fails. */
// static bool install_page(void* upage, void* kpage, bool writable) {
//   struct thread* t = thread_current();

//   /* Verify that there's not already a page at that virtual
//      address, then map our page there. */
//   return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
//           pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
// }

// /* Returns true if t is the main thread of the process p */
// bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

// /* Gets the PID of a process */
// pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

// /* Creates a new stack for the thread and sets up its arguments.
//    Stores the thread's entry point into *EIP and its initial stack
//    pointer into *ESP. Handles all cleanup if unsuccessful. Returns
//    true if successful, false otherwise.

//    This function will be implemented in Project 2: Multithreading. For
//    now, it does nothing. You may find it necessary to change the
//    function signature. */
// // bool setup_thread(void (**eip)(void) UNUSED, void** esp UNUSED) { return false; }
// bool setup_thread(void (**eip)(void), void** esp) {

//   uint8_t* vaddr = PHYS_BASE - PGSIZE;
//   int num_stack_pages = 0;
//   // TODO: check MAX_STACK_PAGES
//   while (vaddr > 0 && num_stack_pages < MAX_STACK_PAGES) {
//     if (pagedir_get_page(thread_current()->pcb->pagedir, vaddr) == NULL) {
//       break;
//     }
//     vaddr = (char *) vaddr - PGSIZE;
//     num_stack_pages++;
//   }
//   if (vaddr <= 0 || num_stack_pages >= MAX_STACK_PAGES) {
//     return false;
//   }
//   *esp = (char *) vaddr + PGSIZE;
//   // // TODO
//   uint8_t* kpage;
//   // bool success = false;

//   kpage = palloc_get_page(PAL_USER | PAL_ZERO);
//   if (kpage == NULL) {
//     return false;
//   }
//   bool success = install_page(vaddr, kpage, true);
//   // printf("installed a page with uaddr %x and kpage %x\n", vaddr, kpage);
//   if (!success) {
//     palloc_free_page(kpage);
//   }
//   // if (kpage != NULL) {
//   //   success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
//   // return true;
//   return success;
// }

// /* Starts a new thread with a new user stack running SF, which takes
//    TF and ARG as arguments on its user stack. This new thread may be
//    scheduled (and may even exit) before pthread_execute () returns.
//    Returns the new thread's TID or TID_ERROR if the thread cannot
//    be created properly.

//    This function will be implemented in Project 2: Multithreading and
//    should be similar to process_execute (). For now, it does nothing.
//    */
// // tid_t pthread_execute(stub_fun sf UNUSED, pthread_fun tf UNUSED, void* arg UNUSED) { // return -1; // starter code}

// static void start_pthread_funsies(void* exec_);

// tid_t pthread_execute_funsies(stub_fun sf, pthread_fun tf, void* arg) { 
//   // char* fn_copy;
//   tid_t tid;

//   /* Make a copy of FILE_NAME.
//      Otherwise there's a race between the caller and load(). */
//   // fn_copy = palloc_get_page(0);
//   // if (fn_copy == NULL)
//   //   return -1;
//   // strlcpy(fn_copy, file_name, PGSIZE);

//   // struct process_status* child_status = palloc_get_page(0);
//   // if (child_status == NULL) {
//   //   palloc_free_page(fn_copy);
//   //   return -1; 
//   // }

//   // // initializes the child's process_status
//   // lock_init(&(child_status->lock));
//   // sema_init(&(child_status->sema), 0);
//   // child_status->ref_cnt = 2; 

//   // struct to pass in as an argument to start_process, since it only takes one void* argument
//   struct start_pthread_arg* sparg = palloc_get_page(0);
//   if (sparg == NULL) {
//     // palloc_free_page(fn_copy);
//     // palloc_free_page(child_status);
//     return -1; 
//   }
//   // stub_fun sf;
//   // pthread_fun tf;
//   // struct process* pcb;
//   // bool success; // not in design doc
//   // struct semaphore sema; // not in design doc
//   // void* arg; //can be NULL
//   sparg->sf = sf;
//   sparg->tf = tf;
//   sparg->pcb = thread_current()->pcb;
//   sparg->arg = arg;
//   sema_init(&(sparg->sema), 0);


//   // arg -> file_name = fn_copy;
//   // arg -> child_status = child_status;

//   /* Create a new thread to execute FILE_NAME. */
//   tid = thread_create(thread_current()->name, PRI_DEFAULT, start_pthread_funsies, sparg);
//   sema_down(&(sparg->sema));
//   if (tid == TID_ERROR) {
//     palloc_free_page(sparg);
//     return TID_ERROR;
//   }

//   // struct join_struct* sema_and_thread = palloc_get_page(0);

//   // if (sema_and_thread == NULL) {
//   //   palloc_free_page(sparg);
//   //   return TID_ERROR;
//   // }

//   // sema_and_thread->tid = tid;
//   // sema_init(&(sema_and_thread->join_sema), 0); // joining is allowed now?? not sure

//   // lock_acquire(&(thread_current()->pcb->join_list_lock));
//   // // add the new join struct to our join struct list
//   // list_push_back(&(thread_current()->pcb->join_list), &(sema_and_thread->elem));
//   // lock_release(&(thread_current()->pcb->join_list_lock));

//   return tid;
// }

// static void start_pthread_funsies(void* exec_) {

//   struct start_pthread_arg* sparg = (struct start_pthread_arg*) exec_;
//   stub_fun sf = sparg->sf;
//   pthread_fun tf = sparg->tf;
//   thread_current()->pcb = sparg->pcb;

//   lock_acquire(&(sparg->pcb->threads_list_lock));
//   // enum intr_level old_level = intr_disable();
  
//   list_push_back(&(sparg->pcb->threads_list), &(thread_current()->im_a_thread_elem));
//   lock_release(&(sparg->pcb->threads_list_lock));
//   // intr_set_level(old_level);

//   struct list_elem *e;
//   for (e = list_begin(&(sparg->pcb->threads_list)); e != list_end(&(sparg->pcb->threads_list)); e = list_next(e)) {

//   }

//   void* arg = sparg->arg;

//   struct intr_frame if_;
//   bool success;
  
//   memset(&if_, 0, sizeof if_);
//   if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
//   if_.cs = SEL_UCSEG;
//   if_.eflags = FLAG_IF | FLAG_MBS;

//   process_activate();
//   success = setup_thread(&if_.eip, &if_.esp);

//   if (!success) {
//     // what happens here?
//     return TID_ERROR;
//   }

//   if_.eip = sparg->sf;
//   thread_current()->user_stack_pointer = if_.esp;

//   sema_up(&(sparg->sema));

//   // pushing arguments onto the stack (arg, then tf)
//   // are we supposed to do it character by character; then pointers to the args after?
//   if_.esp = (char *) if_.esp - 4;
//   int32_t* sendhelp = (int32_t*) if_.esp;
//   *sendhelp = arg;
//   if_.esp = (char *) if_.esp - 4;
//   sendhelp = (int32_t*) if_.esp;
//   // *sendhelp = &tf; ???
//   *sendhelp = tf;

//   // fake return address?
//   if_.esp = (char *) if_.esp - 4;
//   int32_t zero = 0;
//   sendhelp = (int32_t *) if_.esp;
//   *sendhelp = zero;

//   // *esp -= 4;
//   // int** int_esp = (int**) esp;
//   // **int_esp = (int) *esp + 4;

//   // sf(tf, arg);
//   // struct list_elem *e;

//   asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
//   NOT_REACHED();


//   // char* file_name = arg->file_name;
//   // struct process_status* p_status = arg->child_status;
//   // struct thread* t = thread_current();
//   // struct intr_frame if_;
//   // bool success, pcb_success;

//   // /* Allocate process control block */
//   // struct process* new_pcb = malloc(sizeof(struct process));
//   // success = pcb_success = new_pcb != NULL;
  
//   // /* Initialize process control block */
//   // if (success) {
//   //   new_pcb->my_own = p_status;
//   //   list_init(&(new_pcb->children));

//   //   // Ensure that timer_interrupt() -> schedule() -> process_activate()
//   //   // does not try to activate our uninitialized pagedir
//   //   new_pcb->pagedir = NULL;
//   //   t->pcb = new_pcb;

//   //   // Continue initializing the PCB as normal
//   //   t->pcb->main_thread = t;
//   //   strlcpy(t->pcb->process_name, t->name, sizeof t->name);

//   //   // our first available file descriptor is 3 because 0, 1, and 2 are reserved for stdin, stdout, stderr
//   //   new_pcb->fd_index = 3;
//   //   // set mappings of 0, 1, and 2 to null because they don't correspond to acutal files
//   //   new_pcb->fd_table[0] = NULL;
//   //   new_pcb->fd_table[1] = NULL;
//   //   new_pcb->fd_table[2] = NULL;

//   //   // USER THREADS initialization

//   //   list_init(&(new_pcb->threads_list));
//   //   list_init(&(new_pcb->join_list));
//   //   list_init(&(new_pcb->user_sema_list));
//   //   list_init(&(new_pcb->user_lock_list));
//   //   new_pcb->lock_counter = 0;
//   //   new_pcb->sema_counter = 0;

//     // calloc remaining structs? or not
//   // }

//   // /* Initialize interrupt frame and load executable. */
//   // if (success) {
//   //   memset(&if_, 0, sizeof if_);
//   //   if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
//   //   if_.cs = SEL_UCSEG;
//   //   if_.eflags = FLAG_IF | FLAG_MBS;

//   //   /* save our existing FPU of the current process in a temporary local 27-int array variable, 
//   //   initialize the FPU with fninit, save the contents of the FPU into the intr_frame struct, 
//   //   then restore the contents of our FPU from the temporary variable */
//   //   uint32_t tempfpu[27];
//   //   asm volatile ("fsave (%0); fninit; fsave (%1); frstor (%0)" : : "g"(&tempfpu), "g"(&if_.fpu));
//   //   success = load(file_name, &if_.eip, &if_.esp);
//   // }

//   // p_status->load_success = success;
//   // sema_up(&(p_status->sema));

//   // /* Handle failure with succesful PCB malloc. Must free the PCB */
//   // if (!success && pcb_success) {
//   //   // Avoid race where PCB is freed before t->pcb is set to NULL
//   //   // If this happens, then an unfortuantely timed timer interrupt
//   //   // can try to activate the pagedir, but it is now freed memory
//   //   struct process* pcb_to_free = t->pcb;
//   //   t->pcb = NULL;
//   //   free(pcb_to_free);
//   // }

//   // /* Clean up. Exit on failure or jump to userspace */
//   // palloc_free_page(file_name);
//   // palloc_free_page(sp_arg);
//   // if (!success) {
//   //   palloc_free_page(p_status);
//   //   thread_exit();
//   // }

//   // /* Start the user process by simulating a return from an
//   //    interrupt, implemented by intr_exit (in
//   //    threads/intr-stubs.S).  Because intr_exit takes all of its
//   //    arguments on the stack in the form of a `struct intr_frame',
//   //    we just point the stack pointer (%esp) to our stack frame
//   //    and jump to it. */
//   // asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
//   // NOT_REACHED();

// }

// // tid_t pthread_execute(stub_fun sf, pthread_fun tf, void* arg) { 

// //   tid_t tid;
  
// //   // we need to free this sometime
// //   struct start_pthread_arg* start_arg = palloc_get_page(0);
// //   if (start_arg == NULL) {
// //     return -1; 
// //   }

// //   start_arg->sf = sf;
// //   start_arg->tf = tf;
// //   start_arg->pcb = thread_current()->pcb;
// //   start_arg->arg = arg;
// //   start_arg->success = false;
// //   sema_init(&(start_arg->sema), 0); // sema-ing starts at 0?
// //   // sema_down(&(start_arg->sema));

// //   // char curr_thread_name[] = thread_current()->name;
// //   // char kt_name[] = "_kernel";
// //   // strcat(curr_thread_name, kt_name);
// //   char* curr_thread_name = thread_current()->name;

// //   printf("called thread_create\n");
// //   sema_init(&(start_arg->sema), 0);
// //   tid = thread_create(curr_thread_name, PRI_DEFAULT, start_pthread, start_arg);
// //   printf("finished from thread_create\n");

// //   printf("sema down prbly doomed\n");
// //   sema_down(&(start_arg->sema));
// //   printf("sema down not doomed\n");

// //   if (tid == TID_ERROR || !start_arg->success) {
// //     palloc_free_page(start_arg);
// //     return -1;
// //   }

// //   struct join_struct* sema_and_thread = calloc(1, sizeof(struct join_struct));

// //   if (sema_and_thread == NULL) {
// //     palloc_free_page(start_arg);
// //     return -1;
// //   }

// //   sema_and_thread->tid = tid;
// //   sema_init(&(sema_and_thread->join_sema), 1); // joining is allowed now?? not sure

// //   // add the new join struct to our join struct list
// //   list_push_back(&(thread_current()->pcb->join_list), &(sema_and_thread->elem));

// //   return tid;
// // }

// /* A thread function that creates a new user thread and starts it
//    running. Responsible for adding itself to the list of threads in
//    the PCB.

//    This function will be implemented in Project 2: Multithreading and
//    should be similar to start_process (). For now, it does nothing. */
// // static void start_pthread(void* exec_ UNUSED) {}
// // static void start_pthread(void* exec_) {

// //   // unpack arguments
// //   struct start_pthread_arg* pt_arg = (struct start_pthread_arg*) exec_;
// //   stub_fun sf = pt_arg->sf;
// //   pthread_fun tf = pt_arg->tf;
  
// //   thread_current()->pcb = pt_arg->pcb;

// //   list_push_back(&(pt_arg->pcb->threads_list), &(thread_current()->im_a_thread_elem));

// //   struct semaphore sema = pt_arg->sema;
// //   void* arg = pt_arg->arg;

// //   struct intr_frame if_;
// //   bool success;
  
// //   memset(&if_, 0, sizeof if_);
// //   if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
// //   if_.cs = SEL_UCSEG;
// //   if_.eflags = FLAG_IF | FLAG_MBS;
  
// //   // thread_current()->pcb = some passed in arg;

// //   process_activate();
// //   success = setup_thread(&if_.eip, &if_.esp);

// //   if (!success) {
// //     // what happens here?
// //   }
// //   // sema_init(&(pt_arg->sema), 0);
// //   sema_up(&pt_arg->sema);
// //   printf("sema up-ed successfully%n");

// //   // if_.eip = &pt_arg->sf; ????
// //   if_.eip = &pt_arg->sf;
// //   thread_current()->user_stack_pointer = if_.esp;

// //   // pushing arguments onto the stack (arg, then tf)
// //   // are we supposed to do it character by character; then pointers to the args after?
// //   if_.esp = (char *) if_.esp - 4;
// //   int32_t* sendhelp = (int32_t*) if_.esp;
// //   *sendhelp = arg;
// //   if_.esp = (char *) if_.esp - 4;
// //   sendhelp = (int32_t*) if_.esp;
// //   // *sendhelp = &tf; ???
// //   *sendhelp = tf;

// //   // fake return address?
// //   if_.esp = (char *) if_.esp - 4;
// //   int32_t zero = 0;
// //   sendhelp = (int32_t *) if_.esp;
// //   *sendhelp = zero;

// //   // *esp -= 4;
// //   // int** int_esp = (int**) esp;
// //   // **int_esp = (int) *esp + 4;


// //   asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
// //   NOT_REACHED();
// // }

// /* Waits for thread with TID to die, if that thread was spawned
//    in the same process and has not been waited on yet. Returns TID on
//    success and returns TID_ERROR on failure immediately, without
//    waiting.

//    This function will be implemented in Project 2: Multithreading. For
//    now, it does nothing. */
// // tid_t pthread_join(tid_t tid UNUSED) { return -1; }
// tid_t pthread_join(tid_t tid) {
//   struct process* p = thread_current()->pcb;
//   struct list_elem* e;
//   // for (e = list_begin(&(p->threads_list)); e != list_end(&(p->threads_list)); e = list_next(e)) {

//   // }
//   bool found = false;
//   struct thread* t;
//   for (e = list_begin(&(p->threads_list)); e != list_end(&(p->threads_list)); e = list_next(e)) {
//     struct thread* curr_t = list_entry(e, struct thread, im_a_thread_elem);
//     if (tid == curr_t->tid) {
//       found = true;
//       t = curr_t;
//       break;
//     }
//   }
//   if (!found) {
//     // return TID_ERROR;
//     // ?????? this seems quite sus TODO
//     return 0;
//   }

//   struct join_struct* join = NULL;
//   for (e = list_begin(&(p->join_list)); e != list_end(&(p->join_list)); e = list_next(e)) {
//     join = list_entry(e, struct join_struct, elem);
//     if (tid == join->tid) {
//       sema_down(&(join->join_sema));
//     }
//   }

//   lock_acquire(&p->join_list_lock);
//   if (join == NULL) {
//     // this probably should not happen???
//     printf("we have problems!!!");
//     lock_release(&p->join_list_lock);
//     return TID_ERROR;
//   }
//   list_remove(&join->elem);
//   lock_release(&p->join_list_lock);

//   // return 0;
//   return tid; // check return LOL
// }

// /* Free the current thread's resources. Most resources will
//    be freed on thread_exit(), so all we have to do is deallocate the
//    thread's userspace stack. Wake any waiters on this thread.

//    The main thread should not use this function. See
//    pthread_exit_main() below.

//    This function will be implemented in Project 2: Multithreading. For
//    now, it does nothing. */
// void pthread_exit(void) {

//   struct thread* t = thread_current();
//   struct process* p = t->pcb;

//   lock_acquire(&(p->threads_list_lock));
//   list_remove(&t->im_a_thread_elem);
//   lock_release(&(p->threads_list_lock));

//   if (is_main_thread(t, p)) {
//     pthread_exit_main();
//     return;
//   }
//   void* vaddr = pg_round_down(t->user_stack_pointer) - PGSIZE;
//   void* page = pagedir_get_page(t->pcb->pagedir, vaddr);
//   // this is very broken :')
//   // printf("we would like to free page with vaddr %x and kpage %x\n", vaddr, page);
//   pagedir_clear_page(t->pcb->pagedir, vaddr);
//   palloc_free_page(page);

//   struct list_elem* e;

//   // iterate through our list of children
//   for (e = list_begin(&p->join_list); e != list_end(&p->join_list); e = list_next(e)) {
//     struct join_struct* js = list_entry(e, struct join_struct, elem);
//     if (js->tid == t->tid) {
//       sema_up(&js->join_sema);
//     }
//   }
  
//   // if (is_main_thread(t, p)) {
//   //   for (e = list_begin(&p->join_list); e != list_end(&p->join_list); e = list_next(e)) {
//   //     struct join_struct* js = list_entry(e, struct join_struct, elem);
//   //     pthread_join(js->tid);
//   //   }
//   //   exit_helper(0);
//   // } else {
//   // struct list_elem *e;
  
//   thread_exit();
  
//   // }
//   // free(t->user_stack_pointer);

//   // pagedir_clear_page(t->pcb->pagedir, );
//   // palloc_free_page();

// }

// /* Only to be used when the main thread explicitly calls pthread_exit.
//    The main thread should wait on all threads in the process to
//    terminate properly, before exiting itself. When it exits itself, it
//    must terminate the process in addition to all necessary duties in
//    pthread_exit.

//    This function will be implemented in Project 2: Multithreading. For
//    now, it does nothing. */
// void pthread_exit_main(void) {
//   struct thread* t = thread_current();
//   struct process* p = t->pcb;
//   struct list_elem* e;
  
//   for (e = list_begin(&p->join_list); e != list_end(&p->join_list); e = list_next(e)) {
//     struct join_struct* js = list_entry(e, struct join_struct, elem);
//     if (js->tid == t->tid) {
//       sema_up(&js->join_sema);
//     }
//   }
//   for (e = list_begin(&p->join_list); e != list_end(&p->join_list); e = list_next(e)) {
//     struct join_struct* js = list_entry(e, struct join_struct, elem);
//     pthread_join(js->tid);
//   }
  
//   exit_helper(0);
// }


#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include "userprog/syscall.h"

static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp);
bool setup_thread(void (**eip)(void), void** esp);

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;

  /* Kill the kernel if we did not succeed */
  ASSERT(success);

  list_init(&(t->pcb->children));
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  char* fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return -1;
  strlcpy(fn_copy, file_name, PGSIZE);

  struct process_status* child_status = palloc_get_page(0);
  if (child_status == NULL) {
    palloc_free_page(fn_copy);
    return -1; 
  }

  // initializes the child's process_status
  lock_init(&(child_status->lock));
  sema_init(&(child_status->sema), 0);
  child_status->ref_cnt = 2; 

  // struct to pass in as an argument to start_process, since it only takes one void* argument
  struct start_process_arg* arg = palloc_get_page(0);
  if (arg == NULL) {
    palloc_free_page(fn_copy);
    palloc_free_page(child_status);
    return -1; 
  }
  arg -> file_name = fn_copy;
  arg -> child_status = child_status;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, arg);
  sema_down(&(child_status->sema));
  if (tid == TID_ERROR) {
    palloc_free_page(fn_copy);
    palloc_free_page(child_status);
    palloc_free_page(arg);
  }
  if (tid == TID_ERROR || !child_status->load_success) {
    return -1; 
  }
  child_status->pid = tid;

  struct thread* cur = thread_current();
  struct process* p = cur->pcb;
  // add child's process_status to our list of children
  list_push_back(&(p->children), &child_status->elem);


  // struct join_struct* sema_and_thread = palloc_get_page(0);

  // if (sema_and_thread == NULL) {
  //   printf("we have problems!!! in sema nad thread");
  //   // what do we do here??? TODO maybe multimoo
  //   // palloc_free_page(sparg);
  //   return TID_ERROR;
  // }

  // sema_and_thread->tid = tid;
  // sema_init(&(sema_and_thread->join_sema), 0);
  // p->sus_initial_join = sema_and_thread;

  // list_init(&(p->join_list));
  // lock_init(&p->join_list_lock);

  // lock_acquire(&(p->join_list_lock));
  // list_push_back(&(p->join_list), &(sema_and_thread->elem));
  // lock_release(&(p->join_list_lock));

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* sp_arg) {
  struct start_process_arg* arg = (struct start_process_arg*) sp_arg;
  char* file_name = arg->file_name;
  struct process_status* p_status = arg->child_status;
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;

  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;
  
  /* Initialize process control block */
  if (success) {
    new_pcb->my_own = p_status;
    list_init(&(new_pcb->children));

    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;

    // Continue initializing the PCB as normal
    t->pcb->main_thread = t;
    strlcpy(t->pcb->process_name, t->name, sizeof t->name);

    // our first available file descriptor is 3 because 0, 1, and 2 are reserved for stdin, stdout, stderr
    new_pcb->fd_index = 3;
    // set mappings of 0, 1, and 2 to null because they don't correspond to acutal files
    new_pcb->fd_table[0] = NULL;
    new_pcb->fd_table[1] = NULL;
    new_pcb->fd_table[2] = NULL;

    // USER THREADS initialization

    // list_init(&(new_pcb->threads_list));
    
    list_init(&(new_pcb->user_sema_list));
    list_init(&(new_pcb->user_lock_list));
    new_pcb->lock_counter = 0;
    new_pcb->sema_counter = 0;

    // lock_init(&new_pcb->threads_list_lock);
    

    lock_init(&new_pcb->lock_counter_lock);
    lock_init(&new_pcb->sema_counter_lock);


    // lock_acquire(&(new_pcb->threads_list_lock));
    // list_push_back(&(new_pcb->threads_list), &(t->im_a_thread_elem));
    // lock_release(&(new_pcb->threads_list_lock));
    

  // struct join_struct* sema_and_thread = palloc_get_page(0);

  // if (sema_and_thread == NULL) {
  //   printf("we have problems!!! in sema nad thread");
  //   // what do we do here??? TODO maybe multimoo
  //   // palloc_free_page(sparg);
  //   return TID_ERROR;
  // }

  list_init(&(new_pcb->join_list));
  lock_init(&new_pcb->join_list_lock);

  // struct join_struct* sema_and_thread = palloc_get_page(0);
  struct join_struct* sema_and_thread = malloc(sizeof(struct join_struct));
  new_pcb->sus_initial_join = sema_and_thread;

  if (sema_and_thread == NULL) {
    success = false;
  } else {
    sema_and_thread->tid = t->tid;
    sema_init(&(sema_and_thread->join_sema), 0);
    sema_and_thread->has_been_joined = false;
    lock_init(&sema_and_thread->has_been_joined_lock);
    // new_pcb->sus_initial_join = sema_and_thread;

    lock_acquire(&(new_pcb->join_list_lock));
    list_push_back(&(new_pcb->join_list), &(sema_and_thread->elem));
    lock_release(&(new_pcb->join_list_lock));
  }

  

  

    // calloc remaining structs? or not
  }

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;

    /* save our existing FPU of the current process in a temporary local 27-int array variable, 
    initialize the FPU with fninit, save the contents of the FPU into the intr_frame struct, 
    then restore the contents of our FPU from the temporary variable */
    uint32_t tempfpu[27];
    asm volatile ("fsave (%0); fninit; fsave (%1); frstor (%0)" : : "g"(&tempfpu), "g"(&if_.fpu));
    success = load(file_name, &if_.eip, &if_.esp);
  }

  p_status->load_success = success;
  sema_up(&(p_status->sema));

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    free(pcb_to_free);
  }

  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(file_name);
  palloc_free_page(sp_arg);
  if (!success) {
    palloc_free_page(p_status);
    thread_exit();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid UNUSED) {
  struct thread* cur = thread_current();
  struct process* p = cur->pcb;
  struct list_elem* e;
  struct process_status* child_status = NULL;

  // iterate through our list of children
  for (e = list_begin(&p->children); e != list_end(&p->children); e = list_next(e)) {
    struct process_status* p_status = list_entry(e, struct process_status, elem);
    // check if we find a match
    if (p_status->pid == child_pid) {
      child_status = p_status;
      break;
    }
  }

  if (child_status == NULL) {
    return -1;
  }

  sema_down(&child_status->sema);
  int exit_code = child_status->exit_code;
  
  decrement_and_mayhap_free(child_status);
  return exit_code;
}

// decrements the reference count of the given process_status and checks if it is at 0 so that we can free it and remove it from parent's list
void decrement_and_mayhap_free(struct process_status* p_status) {
  lock_acquire(&(p_status->lock));
  int ref_cnt = -- p_status-> ref_cnt;
  lock_release(&(p_status->lock));
  if (ref_cnt == 0) {
    list_remove(&p_status->elem);
    palloc_free_page(p_status);
  }
}

// lets us take care of the exit code before calling process_exit
void exit_helper(int exit_code) {
  struct thread* cur = thread_current();
  process_status_t* mine = cur->pcb->my_own;
  mine->exit_code = exit_code;
  process_exit();
}

/* Free the current process's resources. */
void process_exit(void) {
  struct thread* cur = thread_current();
  uint32_t* pd;

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  process_status_t* mine = cur->pcb->my_own;

  sema_up(&(mine->sema));
  decrement_and_mayhap_free(mine);

  struct process* p = cur->pcb;
  struct list_elem* e;
  
  // iterate through list of children and decrement ref_cnt/check if they can be freed
  for (e = list_begin(&p->children); e != list_end(&p->children);) {
    struct process_status* p_status = list_entry(e, struct process_status, elem);
    struct list_elem* next = list_next(e);
    decrement_and_mayhap_free(p_status);
    e = next;
  }

    // TODO: free the join struct list
  for (e = list_begin(&p->join_list); e != list_end(&p->join_list);) {
    struct join_struct* js = list_entry(e, struct join_struct, elem);
    struct list_elem* next = list_next(e);
    // palloc_free_page(js);
    free(js);
    e = next;
  }
  // palloc_free_page(p->sus_initial_join);

  // free all the locks
  for (e = list_begin(&p->user_lock_list); e != list_end(&p->user_lock_list);) {
    struct WO_DE_LOCK* l = list_entry(e, struct WO_DE_LOCK, lock_elem);
    struct list_elem* next = list_next(e);
    if (lock_held_by_current_thread(&(l->kernel_lock))){
      lock_release(&(l->kernel_lock));
    } 
    free(l);
    e = next;
  }

  for (e = list_begin(&p->user_sema_list); e != list_end(&p->user_sema_list);) {
    struct WO_DE_SEMA* s = list_entry(e, struct WO_DE_SEMA, sema_elem);
    struct list_elem* next = list_next(e);
    // if (lock_held_by_current_thread(&(l->kernel_lock))){
    //   lock_release(&(l->kernel_lock));
    // } 
    free(s);
    e = next;
  }


  // close file descriptors
  for (int i = 0; i < 256; i++) {
    if (p->fd_table[i] != NULL) {
      close(i);
    }
  }

  // TODO: free the join struct list

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;
  cur->pcb = NULL;
  free(pcb_to_free);

  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp, int argc, char* argv[]);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  char* save;
  char* token = strtok_r(file_name, " ", &save);
  int argc = 0;
  char* long_argv[100];
  while (token != NULL) {
    long_argv[argc] = token;
    argc++;
    token = strtok_r(NULL, " ", &save);
  }

  char* argv[argc];
  for (int i = 0; i < argc; i++) {
    argv[i] = long_argv[i];
  }


  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  strlcpy(t->pcb->process_name, argv[0], strlen(argv[0]) + 1);

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }
  file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp, argc, argv))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  file_close(file);
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp_uncasted, int argc, char* argv[]) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success) {
      *esp_uncasted = PHYS_BASE;

      // we need *esp to not be a void* so that we can dereference it
      char** esp = (char **) esp_uncasted;

      int32_t word_addresses[argc];
      // iterate through the arguments. the following loop "put[s] the arguments for the initial function on the stack" (spec)
      for (int i = 0; i < argc; i++) {
        // need to decrement the stack pointer
        *esp -= 1;

        // add a null terminator for the string
        **esp = '\0';

        int len = strlen(argv[i]);
        // iterate through each character to put it on the stack
        for (int j = len - 1; j >= 0; j--) {
          // decrement stack pointer
          *esp -= 1;
          // set memory at address of stack pointer to be this character
          **esp = argv[i][j];
        }

        // save the address of this argument
        word_addresses[i] = *esp;
      }

      int stored = PHYS_BASE - (int) *esp;
      // calculate how many bytes we need to pad for stack alignment after the arguments are added
      int aligned = 16 - ((stored + (argc + 1) * 4 + 8) % 16);
      *esp -= aligned;
      
      // puts null pointer sentinel onto the stack
      *esp -= 4;
      int32_t zero = 0;
      **esp = zero;

      // puts the addresses of each string onto the stack
      for (int i = argc - 1; i >= 0; i--) {
        *esp -= 4;
        int** int_esp = (int**) esp;
        **int_esp = word_addresses[i];
      }

      // puts argv on the stack
      *esp -= 4;
      int** int_esp = (int**) esp;
      **int_esp = (int) *esp + 4;

      // puts argc on the stack
      *esp -= 4;
      **esp = argc;

      // puts "return address" on the stack
      *esp -= 4;
      **esp = 0;
      
    } else {
      palloc_free_page(kpage);
    }
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
// bool setup_thread(void (**eip)(void) UNUSED, void** esp UNUSED) { return false; }
bool setup_thread(void (**eip)(void), void** esp) {

  uint8_t* vaddr = PHYS_BASE - PGSIZE;
  int num_stack_pages = 0;
  // TODO: check MAX_STACK_PAGES
  while (vaddr > 0 && num_stack_pages < MAX_STACK_PAGES) {
    if (pagedir_get_page(thread_current()->pcb->pagedir, vaddr) == NULL) {
      break;
    }
    vaddr = (char *) vaddr - PGSIZE;
    num_stack_pages++;
  }
  if (vaddr <= 0 || num_stack_pages >= MAX_STACK_PAGES) {
    return false;
  }
  *esp = (char *) vaddr + PGSIZE;
  // // TODO
  uint8_t* kpage;
  // bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage == NULL) {
    return false;
  }
  bool success = install_page(vaddr, kpage, true);
  // printf("installed a page with uaddr %x and kpage %x\n", vaddr, kpage);
  if (!success) {
    palloc_free_page(kpage);
  }
  // if (kpage != NULL) {
  //   success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
  // return true;
  return success;
}

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
// tid_t pthread_execute(stub_fun sf UNUSED, pthread_fun tf UNUSED, void* arg UNUSED) { // return -1; // starter code}

static void start_pthread_funsies(void* exec_);

tid_t pthread_execute_funsies(stub_fun sf, pthread_fun tf, void* arg) { 
  // char* fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  // fn_copy = palloc_get_page(0);
  // if (fn_copy == NULL)
  //   return -1;
  // strlcpy(fn_copy, file_name, PGSIZE);

  // struct process_status* child_status = palloc_get_page(0);
  // if (child_status == NULL) {
  //   palloc_free_page(fn_copy);
  //   return -1; 
  // }

  // // initializes the child's process_status
  // lock_init(&(child_status->lock));
  // sema_init(&(child_status->sema), 0);
  // child_status->ref_cnt = 2; 

  // struct to pass in as an argument to start_process, since it only takes one void* argument
  struct start_pthread_arg* sparg = palloc_get_page(0);
  if (sparg == NULL) {
    // palloc_free_page(fn_copy);
    // palloc_free_page(child_status);
    return -1; 
  }
  // stub_fun sf;
  // pthread_fun tf;
  // struct process* pcb;
  // bool success; // not in design doc
  // struct semaphore sema; // not in design doc
  // void* arg; //can be NULL
  sparg->sf = sf;
  sparg->tf = tf;
  sparg->pcb = thread_current()->pcb;
  sparg->arg = arg;
  sema_init(&(sparg->sema), 0);


  // arg -> file_name = fn_copy;
  // arg -> child_status = child_status;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(thread_current()->name, PRI_DEFAULT, start_pthread_funsies, sparg);
  sema_down(&(sparg->sema));
  palloc_free_page(sparg);
  if (tid == TID_ERROR) {
    
    return TID_ERROR;
    // palloc_free_page(fn_copy);
    // palloc_free_page(child_status);
    // palloc_free_page(arg);
  }

  // struct join_struct* sema_and_thread = palloc_get_page(0);

  // if (sema_and_thread == NULL) {
  //   palloc_free_page(sparg);
  //   // return -1;
  //   return TID_ERROR;
  // }

  // sema_and_thread->tid = tid;
  // sema_init(&(sema_and_thread->join_sema), 0); // joining is allowed now?? not sure

  // sema_and_thread->has_been_joined = false;
  // lock_init(&sema_and_thread->has_been_joined_lock);

  // lock_acquire(&(thread_current()->pcb->join_list_lock));
  // // add the new join struct to our join struct list
  // list_push_back(&(thread_current()->pcb->join_list), &(sema_and_thread->elem));
  // lock_release(&(thread_current()->pcb->join_list_lock));

  // PANIC("added to join struct with tid %d", tid);

  return tid;
}

static void start_pthread_funsies(void* exec_) {

  struct start_pthread_arg* sparg = (struct start_pthread_arg*) exec_;
  stub_fun sf = sparg->sf;
  pthread_fun tf = sparg->tf;
  thread_current()->pcb = sparg->pcb;

  // lock_acquire(&(sparg->pcb->threads_list_lock));
  // enum intr_level old_level = intr_disable();
  
  // list_push_back(&(sparg->pcb->threads_list), &(thread_current()->im_a_thread_elem));
  // lock_release(&(sparg->pcb->threads_list_lock));
  // intr_set_level(old_level);

  lock_init(&thread_current()->has_been_joined_lock);

  // struct list_elem *e;
  // for (e = list_begin(&(sparg->pcb->threads_list)); e != list_end(&(sparg->pcb->threads_list)); e = list_next(e)) {

  // }

  // struct join_struct* sema_and_thread = palloc_get_page(0);
  struct join_struct* sema_and_thread = malloc(sizeof(struct join_struct));

  if (sema_and_thread == NULL) {
    // TODO CHECK MULTIOOM T^TTT
    // palloc_free_page(sparg);
    // return -1;
    return TID_ERROR;
  }

  sema_and_thread->tid = thread_current()->tid;
  sema_init(&(sema_and_thread->join_sema), 0); // joining is allowed now?? not sure

  sema_and_thread->has_been_joined = false;
  lock_init(&sema_and_thread->has_been_joined_lock);

  lock_acquire(&(thread_current()->pcb->join_list_lock));
  // add the new join struct to our join struct list
  list_push_back(&(thread_current()->pcb->join_list), &(sema_and_thread->elem));
  lock_release(&(thread_current()->pcb->join_list_lock));

  // PANIC("added to join struct with tid %d", thread_current()->tid);

  void* arg = sparg->arg;

  struct intr_frame if_;
  bool success;
  
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  process_activate();
  success = setup_thread(&if_.eip, &if_.esp);

  if (!success) {
    // what happens here?
    return TID_ERROR;
  }

  if_.eip = sparg->sf;
  thread_current()->user_stack_pointer = if_.esp;

  sema_up(&(sparg->sema));

  // pushing arguments onto the stack (arg, then tf)
  // are we supposed to do it character by character; then pointers to the args after?
  if_.esp = (char *) if_.esp - 4;
  int32_t* sendhelp = (int32_t*) if_.esp;
  *sendhelp = arg;
  if_.esp = (char *) if_.esp - 4;
  sendhelp = (int32_t*) if_.esp;
  // *sendhelp = &tf; ???
  *sendhelp = tf;

  // fake return address?
  if_.esp = (char *) if_.esp - 4;
  int32_t zero = 0;
  sendhelp = (int32_t *) if_.esp;
  *sendhelp = zero;

  // *esp -= 4;
  // int** int_esp = (int**) esp;
  // **int_esp = (int) *esp + 4;

  // sf(tf, arg);
  // struct list_elem *e;

  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();


  // char* file_name = arg->file_name;
  // struct process_status* p_status = arg->child_status;
  // struct thread* t = thread_current();
  // struct intr_frame if_;
  // bool success, pcb_success;

  // /* Allocate process control block */
  // struct process* new_pcb = malloc(sizeof(struct process));
  // success = pcb_success = new_pcb != NULL;
  
  // /* Initialize process control block */
  // if (success) {
  //   new_pcb->my_own = p_status;
  //   list_init(&(new_pcb->children));

  //   // Ensure that timer_interrupt() -> schedule() -> process_activate()
  //   // does not try to activate our uninitialized pagedir
  //   new_pcb->pagedir = NULL;
  //   t->pcb = new_pcb;

  //   // Continue initializing the PCB as normal
  //   t->pcb->main_thread = t;
  //   strlcpy(t->pcb->process_name, t->name, sizeof t->name);

  //   // our first available file descriptor is 3 because 0, 1, and 2 are reserved for stdin, stdout, stderr
  //   new_pcb->fd_index = 3;
  //   // set mappings of 0, 1, and 2 to null because they don't correspond to acutal files
  //   new_pcb->fd_table[0] = NULL;
  //   new_pcb->fd_table[1] = NULL;
  //   new_pcb->fd_table[2] = NULL;

  //   // USER THREADS initialization

  //   list_init(&(new_pcb->threads_list));
  //   list_init(&(new_pcb->join_list));
  //   list_init(&(new_pcb->user_sema_list));
  //   list_init(&(new_pcb->user_lock_list));
  //   new_pcb->lock_counter = 0;
  //   new_pcb->sema_counter = 0;

    // calloc remaining structs? or not
  // }

  // /* Initialize interrupt frame and load executable. */
  // if (success) {
  //   memset(&if_, 0, sizeof if_);
  //   if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  //   if_.cs = SEL_UCSEG;
  //   if_.eflags = FLAG_IF | FLAG_MBS;

  //   /* save our existing FPU of the current process in a temporary local 27-int array variable, 
  //   initialize the FPU with fninit, save the contents of the FPU into the intr_frame struct, 
  //   then restore the contents of our FPU from the temporary variable */
  //   uint32_t tempfpu[27];
  //   asm volatile ("fsave (%0); fninit; fsave (%1); frstor (%0)" : : "g"(&tempfpu), "g"(&if_.fpu));
  //   success = load(file_name, &if_.eip, &if_.esp);
  // }

  // p_status->load_success = success;
  // sema_up(&(p_status->sema));

  // /* Handle failure with succesful PCB malloc. Must free the PCB */
  // if (!success && pcb_success) {
  //   // Avoid race where PCB is freed before t->pcb is set to NULL
  //   // If this happens, then an unfortuantely timed timer interrupt
  //   // can try to activate the pagedir, but it is now freed memory
  //   struct process* pcb_to_free = t->pcb;
  //   t->pcb = NULL;
  //   free(pcb_to_free);
  // }

  // /* Clean up. Exit on failure or jump to userspace */
  // palloc_free_page(file_name);
  // palloc_free_page(sp_arg);
  // if (!success) {
  //   palloc_free_page(p_status);
  //   thread_exit();
  // }

  // /* Start the user process by simulating a return from an
  //    interrupt, implemented by intr_exit (in
  //    threads/intr-stubs.S).  Because intr_exit takes all of its
  //    arguments on the stack in the form of a `struct intr_frame',
  //    we just point the stack pointer (%esp) to our stack frame
  //    and jump to it. */
  // asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  // NOT_REACHED();

}

// tid_t pthread_execute(stub_fun sf, pthread_fun tf, void* arg) { 

//   tid_t tid;
  
//   // we need to free this sometime
//   struct start_pthread_arg* start_arg = palloc_get_page(0);
//   if (start_arg == NULL) {
//     return -1; 
//   }

//   start_arg->sf = sf;
//   start_arg->tf = tf;
//   start_arg->pcb = thread_current()->pcb;
//   start_arg->arg = arg;
//   start_arg->success = false;
//   sema_init(&(start_arg->sema), 0); // sema-ing starts at 0?
//   // sema_down(&(start_arg->sema));

//   // char curr_thread_name[] = thread_current()->name;
//   // char kt_name[] = "_kernel";
//   // strcat(curr_thread_name, kt_name);
//   char* curr_thread_name = thread_current()->name;

//   printf("called thread_create\n");
//   sema_init(&(start_arg->sema), 0);
//   tid = thread_create(curr_thread_name, PRI_DEFAULT, start_pthread, start_arg);
//   printf("finished from thread_create\n");

//   printf("sema down prbly doomed\n");
//   sema_down(&(start_arg->sema));
//   printf("sema down not doomed\n");

//   if (tid == TID_ERROR || !start_arg->success) {
//     palloc_free_page(start_arg);
//     return -1;
//   }

//   struct join_struct* sema_and_thread = calloc(1, sizeof(struct join_struct));

//   if (sema_and_thread == NULL) {
//     palloc_free_page(start_arg);
//     return -1;
//   }

//   sema_and_thread->tid = tid;
//   sema_init(&(sema_and_thread->join_sema), 1); // joining is allowed now?? not sure

//   // add the new join struct to our join struct list
//   list_push_back(&(thread_current()->pcb->join_list), &(sema_and_thread->elem));

//   return tid;
// }

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
// static void start_pthread(void* exec_ UNUSED) {}
// static void start_pthread(void* exec_) {

//   // unpack arguments
//   struct start_pthread_arg* pt_arg = (struct start_pthread_arg*) exec_;
//   stub_fun sf = pt_arg->sf;
//   pthread_fun tf = pt_arg->tf;
  
//   thread_current()->pcb = pt_arg->pcb;

//   list_push_back(&(pt_arg->pcb->threads_list), &(thread_current()->im_a_thread_elem));

//   struct semaphore sema = pt_arg->sema;
//   void* arg = pt_arg->arg;

//   struct intr_frame if_;
//   bool success;
  
//   memset(&if_, 0, sizeof if_);
//   if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
//   if_.cs = SEL_UCSEG;
//   if_.eflags = FLAG_IF | FLAG_MBS;
  
//   // thread_current()->pcb = some passed in arg;

//   process_activate();
//   success = setup_thread(&if_.eip, &if_.esp);

//   if (!success) {
//     // what happens here?
//   }
//   // sema_init(&(pt_arg->sema), 0);
//   sema_up(&pt_arg->sema);
//   printf("sema up-ed successfully%n");

//   // if_.eip = &pt_arg->sf; ????
//   if_.eip = &pt_arg->sf;
//   thread_current()->user_stack_pointer = if_.esp;

//   // pushing arguments onto the stack (arg, then tf)
//   // are we supposed to do it character by character; then pointers to the args after?
//   if_.esp = (char *) if_.esp - 4;
//   int32_t* sendhelp = (int32_t*) if_.esp;
//   *sendhelp = arg;
//   if_.esp = (char *) if_.esp - 4;
//   sendhelp = (int32_t*) if_.esp;
//   // *sendhelp = &tf; ???
//   *sendhelp = tf;

//   // fake return address?
//   if_.esp = (char *) if_.esp - 4;
//   int32_t zero = 0;
//   sendhelp = (int32_t *) if_.esp;
//   *sendhelp = zero;

//   // *esp -= 4;
//   // int** int_esp = (int**) esp;
//   // **int_esp = (int) *esp + 4;


//   asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
//   NOT_REACHED();
// }

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
// tid_t pthread_join(tid_t tid UNUSED) { return -1; }
tid_t pthread_join(tid_t tid) {
  struct process* p = thread_current()->pcb;
  struct list_elem* e;

  // bool found = false;
  // struct thread* t;
  // for (e = list_begin(&(p->threads_list)); e != list_end(&(p->threads_list)); e = list_next(e)) {
  //   struct thread* curr_t = list_entry(e, struct thread, im_a_thread_elem);
  //   if (tid == curr_t->tid) {
  //     lock_acquire(&t->has_been_joined_lock);
  //     if (t->has_been_joined) {
  //       lock_release(&t->has_been_joined_lock);
  //       return TID_ERROR;
  //     }
  //     t->has_been_joined = true;
  //     lock_release(&t->has_been_joined_lock);
  //     found = true;
  //     t = curr_t;
  //     break;
  //   }
    
  // }
  // if (!found) {
  //   printf("not found\n");
  //   // return TID_ERROR;
  //   // ??????
  //   return 0;
  // }
  // printf("you will be found (you have been found)\n");
  bool found = false;
  struct join_struct* join = NULL;
  lock_acquire(&p->join_list_lock);
  for (e = list_begin(&(p->join_list)); e != list_end(&(p->join_list)); e = list_next(e)) {
    join = list_entry(e, struct join_struct, elem);
    lock_acquire(&join->has_been_joined_lock);
    if (tid == join->tid) {
      
      if (join->has_been_joined) {
        lock_release(&join->has_been_joined_lock);
        return TID_ERROR;
      }
      found = true;
      join->has_been_joined = true;
      lock_release(&join->has_been_joined_lock);
      // PANIC("before sema down");
      lock_release(&p->join_list_lock);
      sema_down(&(join->join_sema));
      lock_acquire(&p->join_list_lock);
      break;
    } else {
      lock_release(&join->has_been_joined_lock);
    }
  }
  lock_release(&p->join_list_lock);

  if (!found) {
    return TID_ERROR;
  }

  lock_acquire(&p->join_list_lock);
  list_remove(&join->elem);
  // palloc_free_page(join);
  free(join);
  lock_release(&p->join_list_lock);
  

  // lock_acquire(&p->join_list_lock);
  // if (join == NULL) {
  //   // this probably should not happen???
  //   printf("we have problems!!!");
  //   lock_release(&p->join_list_lock);
  //   return TID_ERROR;
  // }
  // list_remove(&join->elem);
  // lock_release(&p->join_list_lock);

  // return 0;
  return tid; // check return LOL
}

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {
  

  struct thread* t = thread_current();
  struct process* p = t->pcb;

  // lock_acquire(&(p->threads_list_lock));
  // list_remove(&t->im_a_thread_elem);
  // lock_release(&(p->threads_list_lock));
  
  if (is_main_thread(t, p)) {
    pthread_exit_main();
    return;
  }
  void* vaddr = pg_round_down(t->user_stack_pointer) - PGSIZE;
  void* page = pagedir_get_page(t->pcb->pagedir, vaddr);
  // this is very broken :')
  // printf("we would like to free page with vaddr %x and kpage %x\n", vaddr, page);
  pagedir_clear_page(t->pcb->pagedir, vaddr);
  palloc_free_page(page);

  struct list_elem* e;

  int num_iters = 0;
  lock_acquire(&(thread_current()->pcb->join_list_lock));  
  for (e = list_begin(&p->join_list); e != list_end(&p->join_list); e = list_next(e)) {
    struct join_struct* js = list_entry(e, struct join_struct, elem);
    if (js->tid == t->tid) {
      // PANIC("before sema up");
      sema_up(&js->join_sema);
      break;
    }
    // printf("sadgness");
    // PANIC("after the for loop with js %d t %d", js->tid, t->tid);
    num_iters++;
  }
  lock_release(&(thread_current()->pcb->join_list_lock));
  // PANIC("after the for loop with %d iters", num_iters);
  
  // if (is_main_thread(t, p)) {
  //   for (e = list_begin(&p->join_list); e != list_end(&p->join_list); e = list_next(e)) {
  //     struct join_struct* js = list_entry(e, struct join_struct, elem);
  //     pthread_join(js->tid);
  //   }
  //   exit_helper(0);
  // } else {
  // struct list_elem *e;
  
  thread_exit();
  
  // }
  // free(t->user_stack_pointer);

  // pagedir_clear_page(t->pcb->pagedir, );
  // palloc_free_page();

}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {
  // printf("i am in pthread exit main\n");
  struct thread* t = thread_current();
  struct process* p = t->pcb;
  struct list_elem* e;
  
  for (e = list_begin(&p->join_list); e != list_end(&p->join_list); e = list_next(e)) {
    struct join_struct* js = list_entry(e, struct join_struct, elem);
    if (js->tid == t->tid) {
      sema_up(&js->join_sema);
    }
  }
  for (e = list_begin(&p->join_list); e != list_end(&p->join_list); e = list_next(e)) {
    struct join_struct* js = list_entry(e, struct join_struct, elem);
    pthread_join(js->tid);
  }
  
  // exit_helper(0);
  exit(0);
}