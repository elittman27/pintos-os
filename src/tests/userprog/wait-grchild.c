/* Tests to confirm that calling wait on a grandchild of a process
    returns -1. The grandchild of a process is not a direct child so
    the process can't wait for it. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
    pid_t child = exec("process-b"); // Process B executes C
    pid_t grandchild = 5; // Process C's id is always 5 (and is checked later)
    msg("wait(child) = %d", wait(child)); // Should work
    msg("wait(grandchild) = %d", wait(grandchild)); // Should return -1
}
