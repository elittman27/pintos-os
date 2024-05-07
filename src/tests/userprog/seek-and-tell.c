/* Check that syscall seek and tell are working.
   First writes to a file and checks if the next byte to read has been modified.
   Then sets the location with seek and checks to see if it is the same with tell.
    */

#include <syscall.h>

#include "tests/lib.h"
#include "tests/main.h"
#include "tests/userprog/sample.inc"

void
test_main (void)
{
  int fd;
  unsigned size;

  CHECK(create ("dummy.txt", (sizeof(sample)) - 1), "create \"dummy.txt\"");
  CHECK((fd = open ("dummy.txt")) > 1, "open \"dummy.txt\"");

  size = write (fd, sample, (sizeof(sample)) - 1);

  if (size != (sizeof(sample)) - 1) {
    fail("write() returned %d instead of %zu", size, (sizeof(sample)) - 1);
  }

  CHECK(tell(fd) == size, "tell \"dummy.txt\"");

  msg("seek \"dummy.txt\"");
  seek(fd, (sizeof(sample)) - 5);
  CHECK((tell(fd)) == (sizeof(sample)) - 5, "tell \"dummy.txt\"");
  
}