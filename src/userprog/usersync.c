#include "userprog/usersync.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <stdio.h>
#include <string.h>
#include "threads/vaddr.h"

int unique_lock_id;
int unique_semaphore_id;

struct lock usersync_lock;

void usersync_init() {
  unique_lock_id = 0;
  unique_semaphore_id = 0;
  lock_init(&usersync_lock);
}

bool sys_lock_init(char* ptr) {
  struct thread* t = thread_current();
  struct process* p = t->pcb;
  ASSERT(p != NULL);

  struct lock_item* new_lock = (struct lock_item*)malloc(sizeof(struct lock_item));

  lock_init(&new_lock->kernel_lock);
  new_lock->lock_ptr = ptr;
  lock_acquire(&usersync_lock);
  *ptr = unique_lock_id;
  new_lock->lock_id = unique_lock_id++;
  list_push_back(&p->user_lock_list, &new_lock->elem);
  lock_release(&usersync_lock);
  return true;
}

bool sys_sema_init(char* ptr, int val) {
  struct thread* t = thread_current();
  struct process* p = t->pcb;
  ASSERT(p != NULL);

  struct semaphore_item* new_sema = (struct semaphore_item*)malloc(sizeof(struct semaphore_item));

  sema_init(&new_sema->kernel_semaphore, val);
  new_sema->sema_ptr = ptr;
  lock_acquire(&usersync_lock);
  *ptr = unique_semaphore_id;
  new_sema->sema_id = unique_semaphore_id++;
  list_push_back(&p->user_sema_list, &new_sema->elem);
  lock_release(&usersync_lock);
  return true;
}

void sys_lock_acquire(char* ptr) {
  struct thread* t = thread_current();
  struct process* p = t->pcb;
  lock_acquire(&usersync_lock);
  bool found_lock = false;
  struct lock_item* found_lock_item = NULL;

  for (struct list_elem* e = list_begin(&p->user_lock_list);
       e != list_end(&p->user_lock_list); e = list_next(e)) {
    struct lock_item* entry = list_entry(e, struct lock_item, elem);
    if (entry->lock_ptr == ptr) {
      found_lock_item = entry;
      found_lock = true;
      break;
    }
  }

  lock_release(&usersync_lock);

  if (!found_lock) {
    do_exit(1);
  } else {
    if (lock_held_by_current_thread(&found_lock_item->kernel_lock)) {
        do_exit(1);
    }
    lock_acquire(&found_lock_item->kernel_lock);
  }
}

void sys_lock_release(char* ptr) {
  struct thread* t = thread_current();
  struct process* p = t->pcb;
  lock_acquire(&usersync_lock);
  bool found_lock = false;
  struct lock_item* found_lock_item = NULL;

  for (struct list_elem* e = list_begin(&p->user_lock_list);
       e != list_end(&p->user_lock_list); e = list_next(e)) {
    struct lock_item* entry = list_entry(e, struct lock_item, elem);
    if (entry->lock_ptr == ptr) {
      found_lock_item = entry;
      found_lock = true;
      break;
    }
  }

  lock_release(&usersync_lock);

  if (!found_lock) {
    do_exit(1);
  } else {
    lock_release(&found_lock_item->kernel_lock);
  }
}

void sys_sema_up(char* ptr) {
  struct thread* t = thread_current();
  struct process* p = t->pcb;
  lock_acquire(&usersync_lock);
  bool found_sema = false;
  struct semaphore_item* found_sema_item = NULL;

  for (struct list_elem* e = list_begin(&p->user_sema_list);
       e != list_end(&p->user_sema_list); e = list_next(e)) {
    struct semaphore_item* entry = list_entry(e, struct semaphore_item, elem);
    if (entry->sema_ptr == ptr) {
      found_sema_item = entry;
      found_sema  = true;
      break;
    }
  }

  lock_release(&usersync_lock);

  if (!found_sema) {
    do_exit(1);
  } else {
    sema_up(&found_sema_item->kernel_semaphore);
  }
}

void sys_sema_down(char* ptr) {
  struct thread* t = thread_current();
  struct process* p = t->pcb;
  lock_acquire(&usersync_lock);
  bool found_sema = false;
  struct semaphore_item* found_sema_item = NULL;

  for (struct list_elem* e = list_begin(&p->user_sema_list);
       e != list_end(&p->user_sema_list); e = list_next(e)) {
    struct semaphore_item* entry = list_entry(e, struct semaphore_item, elem);
    if (entry->sema_ptr == ptr) {
      found_sema_item = entry;
      found_sema  = true;
      break;
    }
  }

  lock_release(&usersync_lock);

  if (!found_sema) {
    do_exit(1);
  } else {
    sema_down(&found_sema_item->kernel_semaphore);
  }
}