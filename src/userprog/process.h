#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* Item indicating a process chlid to be stored in a list */
/* Includes shared synchronization primitives */
/* Semaphores to control running of the process */
/* Locks to create critical sections for the semaphore */
/* Reference counts to control freeing of the process */
struct process_child_item {
  struct semaphore semaphore;
  struct lock lock;
  size_t ref_cnt;
  pid_t pid;
  char* file_name;
  bool successful_load;
  bool waited;
  int exit_code;
  struct list_elem elem;
};

// Item representing capabilties to support thread_join and so on
struct user_thread_item {
  struct lock lock;
  struct semaphore semaphore;
  bool waited_on;
  bool needs_to_stop;
  struct thread* thread_ptr;
  struct list_elem elem;
  tid_t tid;
  uint8_t* kernel_page_to_free;
  uint8_t* user_vaddr_to_free;
};



/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;                   /* Page directory. */
  char process_name[16];               /* Name of the main thread */
  struct thread* main_thread;          /* Pointer to main thread */
  struct list children_list;           /* list of children processes */
  struct process_child_item* item_ptr; /* pointer to list_item of parent */
  struct list user_thread_list;         /* list of user threads (user join items) in the process*/

  struct list user_lock_list; /* list of locks from user threads */
  struct list user_sema_list; /* list of semaphores from user threads */

  struct lock lock; /* potentially shared data of the pcb when multiple threads touch*/
  struct lock exit_lock; /* Lock used so that new threads are not added during exit */
  uint8_t* next_page_uaddr; /* next user address to allocate a stack onto */

  int num_user_stacks_allocated;
};

void userprog_init(void);

// do a process exit (prints code and puts exit code on)
void do_exit(int code);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t, bool);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */