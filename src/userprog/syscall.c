#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/usersync.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <stdio.h>
#include <string.h>
#include "threads/vaddr.h"
// #include <unistd.h>

// // Global Lock for File operations sync
struct lock file_lock;

static void syscall_handler(struct intr_frame*);

//list for all the files
struct file_node {
  pid_t file_pid;
  bool is_executable;
  int fd;
  char* name;
  struct file* file_ptr;

  struct list_elem elem;
};

struct list* file_list;

/* frees the file descriptors for a given process id */
void free_file_descriptors_for_process(pid_t pid) {
  const int MAX_NUM_FILES = 200;
  struct file_node* list_elem_buffer[MAX_NUM_FILES];

  int buf_idx = 0;
  for (struct list_elem* e = list_begin(file_list); e != list_end(file_list); e = list_next(e)) {
    struct file_node* file = list_entry(e, struct file_node, elem);
    if (file->file_pid == pid) {
      list_elem_buffer[buf_idx++] = file;
    }
  }

  for (int i = 0; i < buf_idx; i++) {
    struct file_node* ptr = list_elem_buffer[i];
    list_remove(&ptr->elem);
    file_close(ptr->file_ptr);
    free(ptr->name);
    free(ptr);
  }
};

/*global fd counter. I increment this every call to open. Pretty shit way of getting next available fd*/
static int fdCounter = 3;

/*debugger function that prints out some imp contents of file_list
Idt it works.
*/
static void print_file_list() {

  for (struct list_elem* iter = list_begin(file_list); iter != list_tail(file_list);
       iter = list_next(iter)) {

    struct file_node* cur_file_node = list_entry(iter, struct file_node, elem);
    printf("file name: %s. fd: %d. pid: %d\n", cur_file_node->name, cur_file_node);
  }
}

/*Gets next fd to assign the next opened file*/
int get_next_fd() {
  fdCounter += 1;
  return fdCounter;
}

/*Gets the calling process's pid
Used to assign every fd a corresponding fd so every
process can only access its own fd's*/
pid_t get_cur_pid() { return thread_current()->pcb->main_thread->tid; }

/* Init stuff. I think this was here before I got here wowza.*/
void syscall_init(void) {
  // init lock
  lock_init(&file_lock);
  usersync_init();

  // init the file system used for maintain files across all processes (i think)
  // On second thought, stuff works without it so? maybe don't need

  //init the file list
  file_list = malloc(sizeof(struct list));
  list_init(file_list);

  // stuff that was here before
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*handler for the create syscall*/
static bool syscall_create(char* file_name, int num_bytes) {
  /*Start Arg Val*/
  if (file_name == NULL) {
    do_exit(-1);
  }
  if (strlen(file_name) == 0) {
    do_exit(-1);
  }
  /*End Arg Val*/

  return filesys_create(file_name, num_bytes);
  ;
}

/*handler for the remove syscall*/
static bool syscall_remove(char* file_name) {
  /*Start Arg Val*/
  if (file_name == NULL) {
    do_exit(-1);
  }
  if (strlen(file_name) == 0) {
    do_exit(-1);
  }
  /*End Arg Val*/

  return filesys_remove(file_name);
}

/*handler for the open syscall*/
static int syscall_open(char* file_name) {
  /*Start Arg Val*/
  if (file_name == NULL) {
    return -1;
  }

  if (file_name > PHYS_BASE) {
    do_exit(-1);
  }
  if (!is_user_vaddr(file_name)) {
    do_exit(-1);
  }
  if (strlen(file_name) == 0) {
    return -1;
  }
  /*End Arg Val*/

  struct file* opened_file = filesys_open(file_name);
  if (opened_file == NULL) {
    return -1;
  }

  int new_fd = get_next_fd();

  /*Since we opened file, we need new fd's and new entry on our
  fd table. The following chunk allocates space for a new entry and sets
  all the values*/
  struct file_node* new_file_node = malloc(sizeof(struct file_node));
  struct list_elem new_list_elem;

  new_file_node->elem = new_list_elem;
  new_file_node->fd = new_fd;
  new_file_node->file_pid = get_cur_pid();
  new_file_node->file_ptr = opened_file;

  new_file_node->is_executable = false;

  if (strcmp(thread_current()->pcb->process_name, file_name) == 0) {
    new_file_node->is_executable = true;
    file_deny_write(new_file_node->file_ptr);
  }

  new_file_node->name = malloc(strlen(file_name) + 1);
  strlcpy(new_file_node->name, file_name, sizeof(new_file_node->name));

  list_push_back(file_list, &(new_file_node->elem));

  return new_fd;
}

static void syscall_close(int fd) {
  if (fd < 3) {
    return;
  }

  for (struct list_elem* iter = list_begin(file_list); iter != list_tail(file_list);
       iter = list_next(iter)) {
    struct file_node* cur_file_node = list_entry(iter, struct file_node, elem);
    if (cur_file_node->fd == fd && cur_file_node->file_pid == get_cur_pid()) {
      file_close(cur_file_node->file_ptr);

      list_remove(&(cur_file_node->elem));
      free(cur_file_node->name);
      free(cur_file_node);
      return;
    }
  }
}

/*handler for the filesize syscall*/
static int syscall_filesize(int fd) {

  if (fd < 3) {
    return -1;
  }

  for (struct list_elem* iter = list_begin(file_list); iter != list_tail(file_list);
       iter = list_next(iter)) {

    struct file_node* cur_file_node = list_entry(iter, struct file_node, elem);

    if (cur_file_node->fd == fd && cur_file_node->file_pid == get_cur_pid()) {
      return file_length(cur_file_node->file_ptr);
    }
  }
  return -1;
}

/*handler for read syscall*/
static int syscall_read(int fd, void* buffer, unsigned size) {
  for (struct list_elem* iter = list_begin(file_list); iter != list_tail(file_list);
       iter = list_next(iter)) {

    struct file_node* cur_file_node = list_entry(iter, struct file_node, elem);
    if (cur_file_node->fd == fd && cur_file_node->file_pid == get_cur_pid()) {
      int ret = file_read(cur_file_node->file_ptr, buffer, size);
      return ret;
    }
  }
  return -1;
}

/*handler for the write syscall*/
static int syscall_write(int fd, void* buffer, unsigned size) {
  if (fd == 0) {
    do_exit(-1);
  }
  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  }
  for (struct list_elem* iter = list_begin(file_list); iter != list_tail(file_list);
       iter = list_next(iter)) {
    struct file_node* cur_file_node = list_entry(iter, struct file_node, elem);
    if (cur_file_node->fd == fd && cur_file_node->file_pid == get_cur_pid()) {
      int ret = file_write(cur_file_node->file_ptr, buffer, size);
      return ret;
    }
  }
  return -1;
}

static void syscall_seek(int fd, unsigned pos) {
  if (fd < 3) {
    return;
  }

  for (struct list_elem* iter = list_begin(file_list); iter != list_tail(file_list);
       iter = list_next(iter)) {
    struct file_node* cur_file_node = list_entry(iter, struct file_node, elem);
    if (cur_file_node->fd == fd && cur_file_node->file_pid == get_cur_pid()) {
      file_seek(cur_file_node->file_ptr, pos);
      return;
    }
  }
}

static int syscall_tell(int fd) {
  if (fd < 3) {
    return -1;
  }

  for (struct list_elem* iter = list_begin(file_list); iter != list_tail(file_list);
       iter = list_next(iter)) {
    struct file_node* cur_file_node = list_entry(iter, struct file_node, elem);
    if (cur_file_node->fd == fd && cur_file_node->file_pid == get_cur_pid()) {
      return file_tell(cur_file_node->file_ptr);
    }
  }
}

bool is_bad_address(void* addr) {
  return !is_user_vaddr(addr) || pagedir_get_page(thread_current()->pcb->pagedir, addr) == NULL;
}

bool is_bad_string(char* addr) {
  while (true) {
    if (is_bad_address(addr)) {
      return true;
    } else if (*((char*)pagedir_get_page(thread_current()->pcb->pagedir, addr)) == '\0') {
      break;
    }
    addr = addr + 1;
  }
  return false;
}

static void syscall_handler(struct intr_frame* f UNUSED) {

  // TODO: Initial argument validation
  if (!is_user_vaddr(f->esp) || pagedir_get_page(thread_current()->pcb->pagedir, f->esp) == NULL) {
    do_exit(-1);
  }
  for (int j = 0; j < sizeof(uint32_t); j++) {
    if (is_bad_address(((char*)(f->esp)) + j)) {
      do_exit(-1);
    }
  }

  uint32_t* args = ((uint32_t*)f->esp);

  // validate the individual addresses for each argument given the num arguments
  const int num_args[] = {
      0, // HALT
      2, // EXIT
      2, // EXEC
      2, // WAIT
      2, // CREATE
      2, // REMOVE
      2, // OPEN
      2, // READ
      4, // WRITE
      2, // SEEK
      2, // TELL
      2, // CLOSE
      2, // PRACTICE
      2, // COMPUTE_E
      4, // SYS_PT_CREATE
      1, // SYS_PT_EXIT,
      2, // SYS_PT_JOIN,
      2, // SYS_LOCK_INIT,
      2, // SYS_LOCK_ACQUIRE,
      2, // SYS_LOCK_RELEASE,
      3, // SYS_SEMA_INIT,
      2, // SYS_SEMA_DOWN,
      2, // SYS_SEMA_UP,
      1  // SYS_GET_TID,
  };

  for (int i = 0; i < num_args[args[0]]; i++) {
    for (int j = 0; j < sizeof(uint32_t); j++) {
      if (is_bad_address(((char*)&args[i]) + j)) {
        do_exit(-1);
      }
    }
  }

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  switch (args[0]) {
    case SYS_EXIT:
      do_exit(args[1]);
      break;
    case SYS_PRACTICE:
      f->eax = args[1] + 1;
      break;
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_CREATE:
      if (is_bad_string(args[1])) {
        do_exit(-1);
      }
      old_lock_acquire(&file_lock);
      f->eax = syscall_create(args[1], args[2]);
      old_lock_release(&file_lock);
      break;
    case SYS_REMOVE:
      if (is_bad_string(args[1])) {
        do_exit(-1);
      }
      old_lock_acquire(&file_lock);
      f->eax = syscall_remove(args[1]);
      old_lock_release(&file_lock);
      break;
    case SYS_OPEN:
      if (is_bad_address(args[1])) {
        do_exit(-1);
      }
      old_lock_acquire(&file_lock);
      f->eax = syscall_open(args[1]);
      old_lock_release(&file_lock);
      break;
    case SYS_FILESIZE:
      old_lock_acquire(&file_lock);
      f->eax = syscall_filesize(args[1]);
      old_lock_release(&file_lock);
      break;
    case SYS_READ:
      if (is_bad_string(args[2])) {
        do_exit(-1);
      }
      old_lock_acquire(&file_lock);
      f->eax = syscall_read(args[1], args[2], args[3]);
      old_lock_release(&file_lock);
      break;
    case SYS_WRITE:
      if (is_bad_string(args[2])) {
        do_exit(-1);
      }
      old_lock_acquire(&file_lock);
      f->eax = syscall_write(args[1], args[2], args[3]);
      old_lock_release(&file_lock);
      break;
    case SYS_SEEK:
      old_lock_acquire(&file_lock);
      syscall_seek(args[1], args[2]);
      old_lock_release(&file_lock);
      break;
    case SYS_TELL:
      old_lock_acquire(&file_lock);
      f->eax = syscall_tell(args[1]);
      old_lock_release(&file_lock);
      break;
    case SYS_CLOSE:
      old_lock_acquire(&file_lock);
      syscall_close(args[1]);
      old_lock_release(&file_lock);
      break;
    case SYS_EXEC:
      char* executing_cmd = args[1];
      if (is_bad_string(executing_cmd)) {
        do_exit(-1);
      }
      f->eax = process_execute(executing_cmd);
      break;
    case SYS_WAIT:
      int child_pid = args[1];
      f->eax = process_wait(child_pid);
      break;
    case SYS_COMPUTE_E:
      f->eax = sys_sum_to_e(args[1]);
      break;
    case SYS_PT_CREATE:
      f->eax = pthread_execute(args[1], args[2], args[3]);
      break;
    case SYS_PT_EXIT:
      if (is_main_thread(thread_current(), thread_current()->pcb)) {
        pthread_exit_main();
      } else {
        pthread_exit();
      }
      break;
    case SYS_PT_JOIN:
      f->eax = pthread_join(args[1], true);
      break;
    case SYS_LOCK_INIT:
      f->eax = sys_lock_init(args[1]);
      break;
    case SYS_LOCK_ACQUIRE:
      sys_lock_acquire(args[1]);
      f->eax = true;
      break;
    case SYS_LOCK_RELEASE:
      sys_lock_release(args[1]);
      f->eax = true;
      break;
    case SYS_SEMA_INIT:
      f->eax = sys_sema_init(args[1], args[2]);
      break;
    case SYS_SEMA_DOWN:
      sys_sema_down(args[1]);
      f->eax = true;
      break;
    case SYS_SEMA_UP:
      sys_sema_up(args[1]);
      f->eax = true;
      break;
    case SYS_GET_TID:
      f->eax = thread_current()->tid;
      break;
  }
}