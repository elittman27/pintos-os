# pintos_os
OS kernel written in C and x86 that schedules processes and threads by priority and synchronizes memory using locks and semaphores. Implemented an extensible file system using inodes and optimized file retrieval with a DRAM buffer cache.

This is a very large project build over months. The most prevalent code samples exist in the following files:
- filesys/filesys.c
- filesys/file.c
- filesys/inode.c
- userprog/process.c
- userprpog/syscall.c