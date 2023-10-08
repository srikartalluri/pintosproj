#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
void free_file_descriptors_for_process(pid_t);

#endif /* userprog/syscall.h */
