/* 
    Test a situation with 4 threads: A, B, C, and D.
        1. Thread A has priority PRI_DEFAULT. A calls `sema_down()` on a semaphore `sema` that was initialized to 1.
                1. current sema value is 0
        2. A creates thread C with priority PRI_DEFAULT + 2. Upon creation of C, A should yield the CPU to C 
            which has higher priority, which will then sema_down() on `sema`. Now, it should block and control 
            should be returned to A.
        3. A creates thread D with priority PRI_DEFAULT + 1. Upon creation of D, A should yield the CPU to D 
            which has higher priority.
        4. D acquires `bdlock` then creates a thread B with priority PRI_DEFAULT + 3. D should yield, and B should run
            since it has highest priority.
        5. B will attempt to acquire `bdlock`. Since D currently holds the lock, B should donate its priority to D.
            B will block while it waits for D to release the lock.
        6. D will run and `sema_down` on `sema`, causing it to block.
        7. A will run again since all the other threads are blocked. A will `sema_up` on `sema`.
        8. Then, since D has the highest effective priority (after donation from B), D should run, printing "I am D, meow".
            D sema ups (but should maintain control of the CPU since it still has higher effective priority than C), 
            then releases the lock.
        9. Releasing the lock allows B to run and also puts D's priority back to its base priority of PRI_DEFAULT + 1.
            B prints "I am B, meow".
        10. After B finishes, C has the highest priority and will run, printing "I am C, meow".
        11. To ensure that all of the threads complete, we have a condition variable that waits until number of threads
            that have finished matches the number of threads created. There is an `update_cond_var()` at the end of each 
            thread's function, where we increment our number of threads finished and signal the condition variable once
            the correct number is hit.
*/

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/thread.h"

#define NUM_THREADS 4

static struct semaphore sema;
static struct lock bdlock;
static struct condition cv;
static struct lock cv_lock;
int num_threads_finished;

static void thread_a_func(void* aux UNUSED);
static void thread_b_func(void* aux UNUSED);
static void thread_c_func(void* aux UNUSED);
static void thread_d_func(void* aux UNUSED);

static void update_cond_var() {
    num_threads_finished++;
    lock_acquire(&cv_lock);
    if (num_threads_finished == NUM_THREADS) {
      cond_signal(&cv, &cv_lock);
    }
    lock_release(&cv_lock);
}

static void thread_a_func(void* aux UNUSED) {
    sema_down(&sema);
    
    msg("I am A, meow");
    thread_create("thread c", PRI_DEFAULT + 2, thread_c_func, NULL);
    thread_create("thread d", PRI_DEFAULT + 1, thread_d_func, NULL);
    sema_up(&sema);
    
    update_cond_var();
}

static void thread_b_func(void* aux UNUSED) {
    lock_acquire(&bdlock);
    msg("I am B, meow");
    update_cond_var();
}

static void thread_c_func(void* aux UNUSED) {
    sema_down(&sema);

    msg("I am C, meow");
    sema_up(&sema);
    update_cond_var();
}

static void thread_d_func(void* aux UNUSED) {
    lock_acquire(&bdlock);
    thread_create("thread b", PRI_DEFAULT + 3, thread_b_func, NULL);
    
    sema_down(&sema);


    msg("I am D, meow");
    sema_up(&sema);
    lock_release(&bdlock);

    update_cond_var();
}

void test_priority_cc5(void) {
  /* This test does not work with the MLFQS. */
  ASSERT(active_sched_policy == SCHED_PRIO);

  sema_init(&sema, 1);
  lock_init(&bdlock);
  cond_init(&cv);
  lock_init(&cv_lock);

  num_threads_finished = 0;
  thread_create("thread a", PRI_DEFAULT, thread_a_func, NULL);

  lock_acquire(&cv_lock);
  while (num_threads_finished != NUM_THREADS) {
    cond_wait(&cv, &cv_lock);
  }
  lock_release(&cv_lock);
}
