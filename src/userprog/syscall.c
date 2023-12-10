#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/usersync.h"
#include "userprog/syscall.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include "threads/vaddr.h"
// #include <unistd.h>

// // Global Lock for File operations sync
struct lock file_lock;

static void syscall_handler(struct intr_frame*);

//list for all the files
struct file_descriptor {
  pid_t file_pid;
  bool is_executable;
  int fd;
  char* name;
  struct file* file_ptr;
  struct dir* dir_ptr;

  bool is_dir;

  struct list_elem elem;
};

struct list* file_list;

/* frees the file descriptors for a given process id */
void free_file_descriptors_for_process(pid_t pid) {
  const int MAX_NUM_FILES = 200;
  struct file_descriptor** list_elem_buffer =
      malloc(sizeof(struct file_descriptor*) * MAX_NUM_FILES);

  int buf_idx = 0;
  for (struct list_elem* e = list_begin(file_list); e != list_end(file_list); e = list_next(e)) {
    struct file_descriptor* file = list_entry(e, struct file_descriptor, elem);
    if (file->file_pid == pid) {
      list_elem_buffer[buf_idx++] = file;
    }
  }

  for (int i = 0; i < buf_idx; i++) {
    struct file_descriptor* ptr = list_elem_buffer[i];
    list_remove(&ptr->elem);
    file_close(ptr->file_ptr);
    free(ptr->name);
    free(ptr);
  }

  free(list_elem_buffer);
};

/*global fd counter. I increment this every call to open. Pretty shit way of getting next available fd*/
static int fdCounter = 3;

/*debugger function that prints out some imp contents of file_list
Idt it works.
*/
static void print_file_list() {

  for (struct list_elem* iter = list_begin(file_list); iter != list_tail(file_list);
       iter = list_next(iter)) {

    struct file_descriptor* cur_file_descriptor = list_entry(iter, struct file_descriptor, elem);
    printf("file name: %s. fd: %d. pid: %d\n", cur_file_descriptor->name, cur_file_descriptor);
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

static bool syscall_mkdir(char* dir_name) {
  if (dir_name == NULL)
    do_exit(-1);

  if (strlen(dir_name) == 0) {
    return false;
  }

  return filesys_mkdir(dir_name);
}

static bool syscall_chdir(char* dir_name) {
  if (dir_name == NULL || strlen(dir_name) == 0) {
    do_exit(-1);
  }
  struct dir* found_dir = NULL;
  bool ret = filesys_open(dir_name, NULL, &found_dir);

  if (found_dir != NULL) {
    dir_close(thread_current()->pcb->cwd);
    thread_current()->pcb->cwd = found_dir;
  }

  return ret;
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

  struct file* opened_file = NULL;
  struct dir* opened_dir = NULL;
  bool operation_result = filesys_open(file_name, &opened_file, &opened_dir);
  if (!operation_result) {
    return -1;
  }

  int new_fd = get_next_fd();

  /*Since we opened file, we need new fd's and new entry on our
  fd table. The following chunk allocates space for a new entry and sets
  all the values*/
  struct file_descriptor* new_file_descriptor = malloc(sizeof(struct file_descriptor));
  struct list_elem new_list_elem;

  new_file_descriptor->elem = new_list_elem;
  new_file_descriptor->fd = new_fd;
  new_file_descriptor->file_pid = get_cur_pid();
  new_file_descriptor->file_ptr = opened_file;
  new_file_descriptor->dir_ptr = opened_dir;
  new_file_descriptor->is_dir = opened_dir != NULL;

  new_file_descriptor->is_executable = false;

  if (strcmp(thread_current()->pcb->process_name, file_name) == 0) {
    new_file_descriptor->is_executable = true;
    file_deny_write(new_file_descriptor->file_ptr);
  }

  new_file_descriptor->name = malloc(strlen(file_name) + 1);
  strlcpy(new_file_descriptor->name, file_name, strlen(new_file_descriptor->name) + 1);

  list_push_back(file_list, &(new_file_descriptor->elem));

  return new_fd;
}

static void syscall_close(int fd) {
  if (fd < 3) {
    return;
  }

  for (struct list_elem* iter = list_begin(file_list); iter != list_tail(file_list);
       iter = list_next(iter)) {
    struct file_descriptor* cur_file_descriptor = list_entry(iter, struct file_descriptor, elem);
    if (cur_file_descriptor->fd == fd && cur_file_descriptor->file_pid == get_cur_pid()) {
      file_close(cur_file_descriptor->file_ptr);

      list_remove(&(cur_file_descriptor->elem));
      free(cur_file_descriptor->name);
      free(cur_file_descriptor);
      return;
    }
  }
}

static bool syscall_isdir(int fd) {
  if (fd < 3) {
    return false;
  }

  for (struct list_elem* iter = list_begin(file_list); iter != list_tail(file_list);
       iter = list_next(iter)) {
    struct file_descriptor* cur_file_descriptor = list_entry(iter, struct file_descriptor, elem);
    if (cur_file_descriptor->fd == fd && cur_file_descriptor->file_pid == get_cur_pid()) {
      return cur_file_descriptor->is_dir;
    }
  }
  return false;
}

static int syscall_inumber(int fd) {
  if (fd < 3) {
    return -1;
  }

  for (struct list_elem* iter = list_begin(file_list); iter != list_tail(file_list);
       iter = list_next(iter)) {
    struct file_descriptor* cur_file_descriptor = list_entry(iter, struct file_descriptor, elem);
    if (cur_file_descriptor->fd == fd && cur_file_descriptor->file_pid == get_cur_pid()) {
      if (cur_file_descriptor->is_dir) {
        return dir_get_inode(cur_file_descriptor->dir_ptr);
      } else {
        return file_get_inode(cur_file_descriptor->file_ptr);
      }
    }
  }
  return false;
}

static bool syscall_readdir(int fd, char name[14 + 1]) {
  if (name == NULL || fd < 3) {
    return false;
  }
  bool found_guy = false;
  for (struct list_elem* iter = list_begin(file_list); iter != list_tail(file_list);
       iter = list_next(iter)) {

    struct file_descriptor* cur_file_descriptor = list_entry(iter, struct file_descriptor, elem);

    if (cur_file_descriptor->fd == fd && cur_file_descriptor->file_pid == get_cur_pid()) {
      if (!cur_file_descriptor->is_dir) {
        do_exit(-1);
      }
      struct dir* current_dir = cur_file_descriptor->dir_ptr;
      while (dir_readdir(current_dir, name)) {
        if (!strcmp(name, "."))
          continue;

        if (!strcmp(name, ".."))
          continue;

        found_guy = true;
        break;
      }
      return found_guy;
    }
    return false;
  }
}

/*handler for the filesize syscall*/
static int syscall_filesize(int fd) {

  if (fd < 3) {
    return -1;
  }

  for (struct list_elem* iter = list_begin(file_list); iter != list_tail(file_list);
       iter = list_next(iter)) {

    struct file_descriptor* cur_file_descriptor = list_entry(iter, struct file_descriptor, elem);

    if (cur_file_descriptor->fd == fd && cur_file_descriptor->file_pid == get_cur_pid()) {
      return file_length(cur_file_descriptor->file_ptr);
    }
  }
  return -1;
}

/*handler for read syscall*/
static int syscall_read(int fd, void* buffer, unsigned size) {
  for (struct list_elem* iter = list_begin(file_list); iter != list_tail(file_list);
       iter = list_next(iter)) {

    struct file_descriptor* cur_file_descriptor = list_entry(iter, struct file_descriptor, elem);
    if (cur_file_descriptor->fd == fd && cur_file_descriptor->file_pid == get_cur_pid()) {
      if (cur_file_descriptor->is_dir) {
        return -1;
      }
      int ret = file_read(cur_file_descriptor->file_ptr, buffer, size);
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
    struct file_descriptor* cur_file_descriptor = list_entry(iter, struct file_descriptor, elem);
    if (cur_file_descriptor->fd == fd && cur_file_descriptor->file_pid == get_cur_pid()) {
      if (cur_file_descriptor->is_dir) {
        return -1;
      }
      int ret = file_write(cur_file_descriptor->file_ptr, buffer, size);
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
    struct file_descriptor* cur_file_descriptor = list_entry(iter, struct file_descriptor, elem);
    if (cur_file_descriptor->fd == fd && cur_file_descriptor->file_pid == get_cur_pid()) {
      file_seek(cur_file_descriptor->file_ptr, pos);
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
    struct file_descriptor* cur_file_descriptor = list_entry(iter, struct file_descriptor, elem);
    if (cur_file_descriptor->fd == fd && cur_file_descriptor->file_pid == get_cur_pid()) {
      return file_tell(cur_file_descriptor->file_ptr);
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
      1, // SYS_GET_TID,
      2, // SYS_MMAP
      2, // SYS_NUMMAP
      2, //  SYS_CHDIR,
      2, //   SYS_MKDIR,
      3, //   SYS_READDIR,
      2, //   SYS_ISDIR,
      2, //   SYS_INUMBER
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
      flush();
      shutdown_power_off();
      break;
    case SYS_CREATE:
      if (is_bad_string(args[1])) {
        do_exit(-1);
      }
      f->eax = syscall_create(args[1], args[2]);
      break;
    case SYS_REMOVE:
      if (is_bad_string(args[1])) {
        do_exit(-1);
      }
      f->eax = syscall_remove(args[1]);
      break;
    case SYS_OPEN:
      if (is_bad_address(args[1])) {
        do_exit(-1);
      }
      f->eax = syscall_open(args[1]);
      break;
    case SYS_FILESIZE:
      f->eax = syscall_filesize(args[1]);
      break;
    case SYS_READ:
      if (is_bad_string(args[2])) {
        do_exit(-1);
      }
      f->eax = syscall_read(args[1], args[2], args[3]);
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
      syscall_seek(args[1], args[2]);
      break;
    case SYS_TELL:
      f->eax = syscall_tell(args[1]);
      break;
    case SYS_CLOSE:
      syscall_close(args[1]);
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
    case SYS_MKDIR:
      f->eax = syscall_mkdir(args[1]);
      break;
    case SYS_CHDIR:
      f->eax = syscall_chdir(args[1]);
      break;
    case SYS_ISDIR:
      f->eax = syscall_isdir(args[1]);
      break;
    case SYS_INUMBER:
      f->eax = syscall_inumber(args[1]);
      break;
    case SYS_READDIR:
      f->eax = syscall_readdir(args[1], args[2]);
      break;
  }
}