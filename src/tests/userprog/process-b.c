/* Child process run by wait-grchild test
   Executes process-c and returns b in hex. */

#include <syscall.h>
#include <stdio.h>
#include "tests/lib.h"

int main(void) {
  test_name = "process-b";
  msg("run");
  pid_t grandchild = exec("process-c");
  CHECK(grandchild == 5, "Check that expected pid for process-c equals its actual pid");
  return 0xb;
}