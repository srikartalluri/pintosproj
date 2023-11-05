#include <stdbool.h>
#include "lib/kernel/list.h"
#include "threads/synch.h"

struct lock_item {
  char* lock_ptr;
  struct lock kernel_lock;
  struct list_elem elem;
  int lock_id;
};

struct semaphore_item {
  char* sema_ptr;
  struct semaphore kernel_semaphore;
  struct list_elem elem;
  int sema_id;
};

void usersync_init(void);
bool sys_lock_init(char* ptr);
void sys_lock_acquire(char* ptr);
void sys_lock_release(char* ptr);
bool sys_sema_init(char* ptr, int val);
void sys_sema_down(char* ptr);
void sys_sema_up(char* ptr);
