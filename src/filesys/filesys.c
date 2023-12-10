#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "list.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();

#ifdef USERPROG
  thread_current()->pcb->cwd = dir_open_root();
#endif
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {
  free_map_close();
  inode_end();
}

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

struct name_info {
  char* name;
  struct list_elem elem;
};

// gets of list of names from path
bool get_list_of_names(const char* path, struct list* lst) {
  // where we are at in the path
  char name_buffer[NAME_MAX + 1];
  char* where_in_path = path;
  int code_start = get_next_part(name_buffer, &where_in_path);
  for (; code_start == 1; code_start = get_next_part(name_buffer, &where_in_path)) {
    char* new_string = (char*)malloc(NAME_MAX + 1);
    strlcpy(new_string, name_buffer, NAME_MAX + 1);

    struct name_info* name_info = (struct name_info*)malloc(sizeof(struct name_info));
    name_info->name = new_string;
    list_push_back(lst, &name_info->elem);
  }
  if (code_start == -1)
    return false;
  return true;
}

// frees the corresponding list of names
int free_list_of_names(struct list* lst) {
  // where we are at in the path
  struct name_info** name_info_buffer = malloc((DEPTH_MAX + 5) * sizeof(struct name_info*));
  int p = 0;
  for (struct list_elem* e = list_begin(lst); e != list_end(lst); e = list_next(e)) {
    struct name_info* name_info = list_entry(e, struct name_info, elem);
    name_info_buffer[p++] = name_info;
  }
  for (int i = 0; i < p; i++) {
    free(name_info_buffer[i]->name);
    free(name_info_buffer[i]);
  }
  free(name_info_buffer);
  return 1;
}

enum operation_t {
  OPERATION_CREATE,
  OPERATION_MKDIR,
  OPERATION_OPEN,
  OPERATION_REMOVE,
};

// traverse the path name name and do the operation operation
bool filesys_traverse(const char* name, off_t initial_size, enum operation_t operation,
                      struct file** store_file, struct dir** store_dir,
                      char store_name[NAME_MAX + 1]) {
  block_sector_t inode_sector = 0;

  struct dir* initial_dir = NULL;

  struct thread* current_thread = thread_current();

  // check that we are in a process and not using an absolute path to start at a cwd
  if (current_thread->pcb != NULL && name[0] != '/') {
    initial_dir = current_thread->pcb->cwd;
  }

  bool is_absolute = initial_dir == NULL;

  struct dir* dir = (is_absolute ? dir_open_root() : initial_dir);

  if (name[0] == '/' && strlen(name) == 1) {
    ASSERT(is_absolute);
    if (operation == OPERATION_OPEN) {
      ASSERT(store_dir != NULL);
      *store_dir = dir;
      return true;
    } else if (operation == OPERATION_REMOVE) {
      dir_close(dir);
      return false;
    }
    // dir_close(dir);
    NOT_REACHED();
  }

  struct list names;
  list_init(&names);
  bool success = get_list_of_names(name, &names);

  struct dir* current_dir = dir;

  if (is_removed(dir_get_inode(current_dir))) {
    if (is_absolute) {
      dir_close(current_dir);
    }
    return false;
  }

  int on_elem = 1;

  int close_these_dirs_ptr = 0;
  struct dir* close_these_dirs[DEPTH_MAX + 1];
  close_these_dirs[close_these_dirs_ptr++] = current_dir;
  for (struct list_elem* e = list_begin(&names); e != list_end(&names);
       e = list_next(e), on_elem++) {
    struct name_info* name_info = (struct name_info*)list_entry(e, struct name_info, elem);
    success &= current_dir != NULL;

    if (on_elem == list_size(&names)) {

      if (operation == OPERATION_CREATE || operation == OPERATION_MKDIR) {
        // create smth new with the free map
        success &=
            free_map_allocate(1, &inode_sector) &&
            (operation == OPERATION_MKDIR
                 ? dir_create(inode_sector, initial_size,
                              inode_get_inumber(dir_get_inode(current_dir)))
                 : inode_create(inode_sector, initial_size)) &&
            dir_add(current_dir, name_info->name, inode_sector, (operation == OPERATION_MKDIR));
        if (!success && inode_sector != 0)
          free_map_release(inode_sector, 1);

      } else if (operation == OPERATION_OPEN) {
        struct inode* inode;
        bool is_dir = false;
        success &= dir_lookup(current_dir, name_info->name, &inode, &is_dir);

        if (success) {
          // can only open a dir if it is intended to open a dir and vice versa
          if (is_dir) {
            if (store_dir != NULL) {
              *store_dir = dir_open(inode);
            } else {
              success = false;
            }
          } else {
            if (store_file != NULL) {
              *store_file = file_open(inode);
            } else {
              success = false;
            }
          }
        }
      } else if (operation == OPERATION_REMOVE) {
        success &= dir_remove(current_dir, name_info->name);
      }
    } else {
      // must be an existing directory
      struct inode* next_inode;
      success &= dir_lookup(current_dir, name_info->name, &next_inode, NULL);
      if (success) {
        current_dir = dir_open(next_inode);
        close_these_dirs[close_these_dirs_ptr++] = current_dir;
      } else {
        break;
      }
    }
  }

  for (int i = (is_absolute ? 0 : 1); i < close_these_dirs_ptr; i++) {
    dir_close(close_these_dirs[i]);
  }

  free_list_of_names(&names);

  return success;
}

const int MAX_NUM_ENTRIES = 16;
/* Creates a directory named NAME with the given INITIAL_SIZE entries.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_mkdir(const char* name) {
  return filesys_traverse(name, MAX_NUM_ENTRIES, OPERATION_MKDIR, NULL, NULL, NULL);
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
  return filesys_traverse(name, initial_size, OPERATION_CREATE, NULL, NULL, NULL);
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_open(const char* name, struct file** file_ret, struct dir** dir_ret) {
  filesys_traverse(name, 0, OPERATION_OPEN, file_ret, dir_ret, NULL);

  return ((file_ret != NULL && *file_ret != NULL) || (dir_ret != NULL && *dir_ret != NULL));
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  return filesys_traverse(name, 0, OPERATION_REMOVE, NULL, NULL, NULL);
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16, ROOT_DIR_SECTOR))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}
