PintOS
=======================

Pintos is an operating system for the x86 architecture. It supports multithreading, loading and running user programs, and a file system, but it implements all of these in a very simple way. 

Pintos could, theoretically, run on a regular IBM-compatible PC, however runs in a system simulator that simulates an x86 CPU and its peripheral devices accurately enough that unmodified operating systems and software can run under it. We use the Bochs2 and QEMU3 simulators.


## User Programs
Supports loading and running user programs with I/O interactivity. We also ensured programs can interact with the kernel through implementation of system calls such as `halt`, `wait`, `exec`, and `exit`.


## Threads
Implemented support for multithreaded user programs with a strict priority scheduler based on a round robin scheduling system. This is done through making a simplified version of the pthread library with functions `pthread_create`, `pthread_exit`, `pthread_join`, and `get_tid`.

Also included synchronization primitives such as locks and semaphores with their respective functions `lock_init`, `lock_acquire`, `lock_release`, `sema_init`, `sema_down`, and `sema_up`

Added functionality for priority donation for locks such that when thread A waits on thread B, thread B's priority gets raised to at least A's. Ensured that priority donation handles 1) donations from multiple sources, 2) undoing the donations after lock has been released, 3) nested donation.

## File Systems
The file system introduces several new syscalls such as `create`, `remove`, `open`, `filesize`, `read`, `write`, `seek`, `tell`, and `close`, each of which interact with files in a thread-safe but file-independent manner (Meaning writing to different files will not wait on each other).

Provided additional support to extend the size of files to allow larger files and fast random accesses to the file. 

Also added functionality to make and manipulate directories through the `chdir`, `mkdir`, `readdir`, `isdir` syscalls. These subdirectories allow for both absolute and relative paths to be used when calling user programs or managing files.

Finally maintained a buffer cache to reduce the number of actual file operations done to disk, and only writing to/read from disk when necessary.

