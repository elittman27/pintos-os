/* Child process run by process-b
   Just prints a single message and returns c in hex. */

#include <stdio.h>
#include "tests/lib.h"

int main(void) {
  test_name = "process-c";
  msg("run");
  return 0xc;
}
