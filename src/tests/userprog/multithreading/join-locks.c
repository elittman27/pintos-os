/* This checks that a lock persists per process and that upon 
joining locks of the joining thread get released.*/

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>
#include <pthread.h>

/* acquire the lock passed in a return */
void thread_function2(void* arg_) {
  msg("Starting thread T2");
  lock_t* lock = (lock_t*) arg_;
  msg("Acquiring lock in T2.");
  msg("Calling join from T1 on T2 should've released the lock.");
  lock_acquire(lock); //checks that join releases joiners locks
  msg("Acquired lock in T2.");
  lock_release(lock);
  msg("Finishing thread T2");
}

/* spawns another thread and aquires a lock*/
void thread_function1(void* arg_) {
    msg("Starting thread T1");
    lock_t lock;
    lock_check_init(&lock);
    lock_acquire(&lock);
    msg("Acquired lock in T1.");
    pthread_check_join(pthread_check_create(thread_function2, &lock));
    lock_acquire(&lock); // Checks pthread exit releases locks.
    msg("Main acquired lock released by T2");
    lock_release(&lock);
    msg("Finishing thread T1");
}

void test_main(void) {
  syn_msg = true;
  msg("Main starting");
  pthread_check_join(pthread_check_create(thread_function1, NULL));
  msg("Main finishing");
}
