/* Check if two syscalls to open will open two seperate file descriptor entries
    that point to the same file however the offset can deviate per file. */

#include <syscall.h>
#include "tests/userprog/sample.inc"
#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void)
{
  int fd1;
  int fd2;
  char buffer[(sizeof(sample))];

  CHECK(create ("dummy", sizeof(sample) - 1), "create \"dummy\"");

  CHECK((fd1=open("dummy")) > 1, "open \"dummy\"");
  CHECK((fd2=open("dummy")) > 1, "open \"dummy\"");

  int write_size=write(fd1, sample, sizeof(sample) - 1);
  int read_size=read(fd2, buffer, sizeof(sample) - 1);
  if(write_size != sizeof(sample) - 1) {
     fail("write() returned %d instead of %zu", write_size, sizeof(sample) - 1);
  }
  if(read_size != sizeof(sample) - 1) {
     fail("read() returned %d instead of %zu", read_size, sizeof(sample) - 1);
  }
  
  if (write_size != read_size){
     fail ("Did not point to the same file.");
  }

  CHECK((tell(fd1)) == tell(fd2), "tell \"dummy\" comparison");
  CHECK((tell(fd1)) != 5, "tell \"dummy\" comparison");
  
  msg("seek \"dummy\"");
  seek(fd1, 5);
  CHECK((tell(fd1)) != tell(fd2), "tell \"dummy\" comparison");
  CHECK((tell(fd1)) ==  5, "tell \"dummy\"");

}