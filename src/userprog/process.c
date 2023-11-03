#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"

static struct semaphore temporary;
static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp);
bool setup_thread(void** esp, void** kpage_set, void** uvaddr_set);
struct user_thread_item* create_user_thread_item(struct thread* t, uint8_t* kpage,
                                                 uint8_t* uvaddr);

// do a process exit under the assumption that all the arguments are valid
void do_exit(int code) {
  struct process_child_item* item = thread_current()->pcb->item_ptr;
  lock_acquire(&item->lock);
  item->exit_code = code;
  lock_release(&item->lock);
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, code);
  process_exit();
}

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;

  list_init(&t->pcb->children_list);
  list_init(&t->pcb->user_thread_list);
  list_init(&t->pcb->user_lock_list);
  list_init(&t->pcb->user_sema_list);
  t->pcb->item_ptr = NULL;
  t->pcb->next_page_uaddr = PHYS_BASE - 2 * PGSIZE;

  struct user_thread_item* main_user_thread_item = create_user_thread_item(t, NULL, NULL);
  list_push_back(&t->pcb->user_thread_list, &main_user_thread_item->elem);
  t->user_thread_item_ptr = main_user_thread_item;

  lock_init(&t->pcb->lock);
  lock_init(&t->pcb->exit_lock);

  /* Kill the kernel if we did not succeed */
  ASSERT(success);
}

// free the file name
void remove_child_reference(struct process_child_item* c) {
  lock_acquire(&c->lock);
  c->ref_cnt--;

  if (c->ref_cnt == 0) {
    lock_release(&c->lock);
    free(c->file_name);
    free(c);
    return;
  }
  lock_release(&c->lock);
  return;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  struct process_child_item* process_child;
  tid_t tid;

  // sema_init(&temporary, 0);
  /* Make a copy of FILE_NAME.  
  Otherwise there's a race between the caller and load(). */
  process_child = (struct process_child_item*)malloc(sizeof(struct process_child_item));
  if (process_child == NULL)
    return TID_ERROR;

  size_t len_of_string = strlen(file_name) + 1;
  process_child->file_name = (char*)malloc(sizeof(char) * (len_of_string));
  strlcpy(process_child->file_name, file_name, len_of_string);
  process_child->ref_cnt = 1;
  process_child->pid = -1;
  process_child->successful_load = true;
  process_child->exit_code = -1;
  process_child->waited = false;
  sema_init(&process_child->semaphore, 0);
  lock_init(&process_child->lock);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, process_child);

  // try to down the semaphore (will be upped by when load executable finishes)
  sema_down(&process_child->semaphore);

  bool successful_load = true;
  lock_acquire(&process_child->lock);
  successful_load = process_child->successful_load;
  lock_release(&process_child->lock);

  if (tid == TID_ERROR || !successful_load) {
    remove_child_reference(process_child);
    // never added to children list because it fails
    return -1;
  } else {
    list_push_back(&thread_current()->pcb->children_list, &process_child->elem);
  }
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* process_item_) {
  struct process_child_item* process_item = (struct process_child_item*)process_item_;

  lock_acquire(&process_item->lock);
  process_item->ref_cnt++;
  lock_release(&process_item->lock);

  char* file_name = process_item->file_name;
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;

  char* save_ptr;
  char* initial_token = strtok_r((char*)file_name, " ", &save_ptr);
  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;

  /* Initialize process control block */
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;
    lock_init(&t->pcb->lock);
    lock_init(&t->pcb->exit_lock);

    // Continue initializing the PCB as normal
    t->pcb->main_thread = t;
    list_init(&t->pcb->children_list);
    list_init(&t->pcb->user_thread_list);
    list_init(&t->pcb->user_lock_list);
    list_init(&t->pcb->user_sema_list);

    struct user_thread_item* main_user_thread_item = create_user_thread_item(t, NULL, NULL);
    list_push_back(&t->pcb->user_thread_list, &main_user_thread_item->elem);
    t->user_thread_item_ptr = main_user_thread_item;

    // set the process name as the initial token
    strlcpy(t->pcb->process_name, initial_token, sizeof t->name);
    t->pcb->item_ptr = process_item;
    t->pcb->next_page_uaddr = PHYS_BASE - 2 * PGSIZE;

    lock_acquire(&process_item->lock);
    process_item->pid = get_pid(t->pcb);
    lock_release(&process_item->lock);
  }

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;

    { // Store an empty fpu in the interrupt frame every switch starts on an empty fpu?
      uint8_t temp_fpu[108];
      asm volatile("fsave (%0)" ::"r"(&temp_fpu));
      asm volatile("finit");

      // store fresh copy in switch frame (switching to fresh fpu)
      asm volatile("fsave (%0)" ::"r"(&if_.fpu));
      asm volatile("frstor (%0)" ::"r"(&temp_fpu));
    }

    // load from the initial token instead of the file_name
    // file_name in this case includes arguments
    success = load(initial_token, &if_.eip, &if_.esp);
    if (!success) {
      lock_acquire(&process_item->lock);
      process_item->successful_load = false;
      lock_release(&process_item->lock);
    }
    sema_up(&process_item->semaphore);

    // now that it's loaded, we don't need to stop the parent from doing aynthing so we can remove our reference to the parent
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    free(pcb_to_free);
  }

  /* Clean up. Exit on failure or jump to userspace */
  // Not a successful load
  if (!success) {
    // sema_up(&temporary);
    sema_up(&process_item->semaphore);
    remove_child_reference(process_item);
    thread_exit();
  }

  /* Setup the userarguments to be above the stack ptr */
  char* token = initial_token;
  int argc = 0;

  // Open ended right bound at the top of the stack
  void* nxt_ptr = PHYS_BASE;

  const int MAX_ITEMS = 200;
  char* arguments_buffer[MAX_ITEMS];

  int item_idx = 0;
  while (token != NULL) {
    argc++;

    // number of bytes in this token
    int num_bytes_of_token = strlen(token) + 1;

    // kvaddr of the relevant argument
    char* copy = (char*)pagedir_get_page(t->pcb->pagedir, nxt_ptr - num_bytes_of_token);

    // setting the location of the item to the corresponding virtual address
    arguments_buffer[item_idx] = nxt_ptr - num_bytes_of_token;

    // copying to kvaddr (we are in the kernel)
    strlcpy(copy, token, num_bytes_of_token);
    // moving open-ended bound of pointer
    nxt_ptr -= num_bytes_of_token;
    token = strtok_r(NULL, " ", &save_ptr);
    item_idx++;
  }

  char** argv = nxt_ptr - (argc + 1) * sizeof(char*);
  {
    for (int i = 0; i < argc; i++) {
      char* entry = arguments_buffer[i];
      char** kernel_argv_ptr = pagedir_get_page(t->pcb->pagedir, argv + i);
      *kernel_argv_ptr = entry;
    }
  }

  { // set kernel argv ptr to be null explicitly (null padding at the end of argv)
    char** kernel_argv_ptr = pagedir_get_page(t->pcb->pagedir, argv + argc);
    kernel_argv_ptr = NULL;
  }

  // make nxt_ptr aligned with the start of the argv array
  // (argc + 1) * sizeof(char*) is the size of the argv array
  nxt_ptr -= (argc + 1) * sizeof(char*);

  // make room for arguments
  if_.esp = nxt_ptr - 12;

  // stack alignment
  while ((uint32_t)(if_.esp) % 16 != 12) {
    if_.esp--;
  }

  int* address_argc = pagedir_get_page(t->pcb->pagedir, if_.esp + 4);
  char*** address_argv = pagedir_get_page(t->pcb->pagedir, if_.esp + 8);
  *address_argc = argc;
  *address_argv = argv;

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid) {
  // sema_down(&temporary);
  struct thread* t = thread_current();

  /*
    1) Look for the child in the pcb children list
    2) Acquire the relevant locks on the shared child item
    3) If the parent is waiting on something already waited for set already waited and return.
      - Child should not set this already waited for feature since parent is supposed to return child's exit code
    4) Down the semaphore to wait
    5) Exit procedure
  */
  bool found_child = false;
  for (struct list_elem* e = list_begin(&t->pcb->children_list);
       e != list_end(&t->pcb->children_list); e = list_next(e)) {
    struct process_child_item* item = list_entry(e, struct process_child_item, elem);
    if (item->pid == child_pid) {
      found_child = true;

      bool already_waited = false;
      lock_acquire(&item->lock);
      if (item->waited)
        already_waited = true;
      lock_release(&item->lock);

      if (already_waited)
        return -1;

      sema_down(&item->semaphore);
      int ret_value = -1;
      lock_acquire(&item->lock);
      ret_value = item->exit_code;
      item->waited = true;
      lock_release(&item->lock);
      return ret_value;
    }
  }

  return -1;
}

/* Free the current process's resources. */
void process_exit(void) {
  struct thread* cur = thread_current();
  uint32_t* pd;

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  int pid = get_pid(cur->pcb);
  struct process* p = cur->pcb;

  lock_acquire(&p->exit_lock);
  for (struct list_elem* e = list_begin(&p->user_thread_list); e != list_end(&p->user_thread_list);
       e = list_next(e)) {
    struct user_thread_item* user_thread_item_here = list_entry(e, struct user_thread_item, elem);
    lock_acquire(&user_thread_item_here->lock);
    user_thread_item_here->needs_to_stop = true;
    lock_release(&user_thread_item_here->lock);
    if (user_thread_item_here->tid != cur->tid) {
     lock_release(&p->exit_lock);
     tid_t ret = pthread_join(user_thread_item_here->tid);
     lock_acquire(&p->exit_lock);
    }
  }
  lock_release(&p->exit_lock);

  /* free the pcb */
  struct process* pcb_to_free = cur->pcb;
  { // free the malloced process_child_items
    struct process_child_item* child_items_buffer[list_size(&pcb_to_free->children_list)];
    // must do the freeing after all the items are in the buffer (cannot do freeing during list traversal)
    int num_items = 0;
    for (struct list_elem* e = list_begin(&pcb_to_free->children_list);
         e != list_end(&pcb_to_free->children_list); e = list_next(e), num_items++) {
      struct process_child_item* entry = list_entry(e, struct process_child_item, elem);
      child_items_buffer[num_items] = entry;
    }

    for (int i = 0; i < num_items; i++) {
      remove_child_reference(child_items_buffer[i]);
    }
  }

  { // free the malloced user_thread_items
    struct user_thread_item* thread_items_buffer[list_size(&pcb_to_free->user_thread_list)];
    // must do the freeing after all the items are in the buffer (cannot do freeing during list traversal)
    int num_items = 0;
    for (struct list_elem* e = list_begin(&pcb_to_free->user_thread_list);
         e != list_end(&pcb_to_free->user_thread_list); e = list_next(e), num_items++) {
      struct user_thread_item* entry = list_entry(e, struct user_thread_item, elem);
      thread_items_buffer[num_items] = entry;
    }

    for (int i = 0; i < num_items; i++) {
      free(thread_items_buffer[i]);
    }
  }

  { // free the malloced lock item items 
    struct lock_item* lock_items_buffer[list_size(&pcb_to_free->user_lock_list)];
    // must do the freeing after all the items are in the buffer (cannot do freeing during list traversal)
    int num_items = 0;
    for (struct list_elem* e = list_begin(&pcb_to_free->user_lock_list);
         e != list_end(&pcb_to_free->user_lock_list); e = list_next(e), num_items++) {
      struct lock_item* entry = list_entry(e, struct lock_item, elem);
      lock_items_buffer[num_items] = entry;
    }

    for (int i = 0; i < num_items; i++) {
      free(lock_items_buffer[i]);
    }
  }

  { // free the malloced sema item items 
    struct semaphore_item* semaphore_items_buffer[list_size(&pcb_to_free->user_sema_list)];
    // must do the freeing after all the items are in the buffer (cannot do freeing during list traversal)
    int num_items = 0;
    for (struct list_elem* e = list_begin(&pcb_to_free->user_sema_list);
         e != list_end(&pcb_to_free->user_sema_list); e = list_next(e), num_items++) {
      struct semaphore_item* entry = list_entry(e, struct semaphore_item, elem);
      semaphore_items_buffer[num_items] = entry;
    }

    for (int i = 0; i < num_items; i++) {
      free(semaphore_items_buffer[i]);
    }
  }

  struct process_child_item* item = cur->pcb->item_ptr;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  cur->pcb = NULL;
  free(pcb_to_free);

  // sema_up(&temporary);
  lock_acquire(&item->lock);
  sema_up(&item->semaphore);
  lock_release(&item->lock);
  remove_child_reference(item);
  free_file_descriptors_for_process(pid);
  thread_exit();
  NOT_REACHED();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  file_close(file);
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void** esp, void** kpage_set, void** uvaddr_set) {
  bool success = false;
  struct thread* t = thread_current();

  // all MAX_CHILD_ITEMSpallocs in project threads should palloc from the kernel pool?
  // https://cs162.org/static/proj/pintos-docs/docs/memory-alloc/page-allocator/
  uint8_t* kpage = palloc_get_page(PAL_ZERO | PAL_USER);
  if (kpage != NULL) {
    lock_acquire(&t->pcb->lock);
    success = install_page(t->pcb->next_page_uaddr - PGSIZE, kpage, true);
    if (success) {
      *esp = t->pcb->next_page_uaddr;
      *kpage_set = kpage;
      *uvaddr_set = t->pcb->next_page_uaddr - PGSIZE;
      t->pcb->next_page_uaddr -= PGSIZE;
    } else {
      palloc_free_page(kpage);
    }
    lock_release(&t->pcb->lock);
  }

  // Must activate the process for thread to have pagedir in process context
  process_activate();
  return success;
}

// run stub_fun on tf, args
// a thread child item with synchronization
struct thread_child_item {
  stub_fun sf;
  pthread_fun tf;
  void* arg;
  struct semaphore startup_semaphore;
  struct lock lock;
  bool succesful_start;
  int ref_cnt;
  struct process* calling_pcb;
};

void remove_thread_reference(struct thread_child_item* c) {
  lock_acquire(&c->lock);
  c->ref_cnt--;

  if (c->ref_cnt == 0) {
    lock_release(&c->lock);
    free(c);
    return;
  }
  lock_release(&c->lock);
  return;
}

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf, pthread_fun tf, void* arg) {
  struct thread_child_item* thread_child;
  tid_t tid;

  // sema_init(&temporary, 0);
  /* Make a copy of FILE_NAME.  
  Otherwise there's a race between the caller and load(). */

  // TODO: Figure out how to free this
  thread_child = (struct thread_child_item*)malloc(sizeof(struct thread_child_item));
  if (thread_child == NULL)
    return TID_ERROR;
  sema_init(&thread_child->startup_semaphore, 0);
  lock_init(&thread_child->lock);
  thread_child->sf = sf;
  thread_child->tf = tf;
  thread_child->arg = arg;
  thread_child->ref_cnt = 1;
  thread_child->succesful_start = true;
  thread_child->calling_pcb = thread_current()->pcb;
  struct process* pcb = thread_child->calling_pcb;

  /* Create a new thread to execute FILE_NAME. */
  char buffer[69];
  lock_acquire(&pcb->lock);
  size_t thread_list_length = list_size(&pcb->user_thread_list);
  lock_release(&pcb->lock);
  snprintf(buffer, 69, "%s | %d", thread_child->calling_pcb->process_name, thread_list_length);
  tid = thread_create(buffer, PRI_DEFAULT, start_pthread, thread_child);

  // try to down the semaphore (will be upped by when load executable finishes)
  sema_down(&thread_child->startup_semaphore);

  bool succesful_start = true;

  lock_acquire(&thread_child->lock);
  succesful_start = thread_child->succesful_start;
  lock_release(&thread_child->lock);

  remove_thread_reference(thread_child);
  if (tid == TID_ERROR || !succesful_start) {
    // never added to children list because it fails
    return TID_ERROR;
  }
  return tid;
}

// acquired t->lock
struct user_thread_item* create_user_thread_item(struct thread* t, uint8_t* kpage,
                                                 uint8_t* uvaddr) {
  // TODO: remember to free this in process_exit
  struct user_thread_item* ret = malloc(sizeof(struct user_thread_item));
  lock_init(&ret->lock);
  sema_init(&ret->semaphore, 0);
  ret->waited_on = false;
  ret->needs_to_stop = false;
  ret->thread_ptr = t;
  ret->tid = t->tid;
  ret->kernel_page_to_free = kpage;
  ret->user_vaddr_to_free = uvaddr;
  return ret;
}

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* exec_) {
  struct thread_child_item* thread_item = (struct thread_child_item*)exec_;

  lock_acquire(&thread_item->lock);
  thread_item->ref_cnt++;
  lock_release(&thread_item->lock);

  struct thread* t = thread_current();
  struct intr_frame if_;
  struct process* pcb = thread_item->calling_pcb;
  t->pcb = pcb;

  bool success = true;

  /* Initialize interrupt frame and load executable. */
  uint8_t *kpage_set, *uvaddr_set;
  {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;

    { // Store an empty fpu in the interrupt frame every switch starts on an empty fpu?
      uint8_t temp_fpu[108];
      asm volatile("fsave (%0)" ::"r"(&temp_fpu));
      asm volatile("finit");

      // store fresh copy in switch frame (switching to fresh fpu)
      asm volatile("fsave (%0)" ::"r"(&if_.fpu));
      asm volatile("frstor (%0)" ::"r"(&temp_fpu));
    }

    // load from the initial token instead of the file_name
    // file_name in this case includes arguments
    if_.eip = thread_item->sf;
    success = setup_thread(&if_.esp, &kpage_set, &uvaddr_set);
    if (!success) {
      lock_acquire(&thread_item->lock);
      thread_item->succesful_start = false;
      lock_release(&thread_item->lock);
    }

    // now that it's loaded, we don't need to stop the parent from doing aynthing so we can remove our reference to the parent
  }

  /* Clean up. Exit on failure or jump to userspace */
  // Not a successful load
  if (!success) {
    remove_thread_reference(thread_item);
    thread_exit();
  }

  lock_acquire(&pcb->lock);
  struct user_thread_item* c = create_user_thread_item(t, kpage_set, uvaddr_set);
  list_push_back(&pcb->user_thread_list, &c->elem);
  t->user_thread_item_ptr = c;
  lock_release(&pcb->lock);

  /* Setup the userarguments to be above the stack ptr */

  // Open ended right bound at the top of the stack
  lock_acquire(&pcb->lock);
  void* nxt_ptr = pcb->next_page_uaddr + PGSIZE;
  lock_release(&pcb->lock);

  // after the thread item has been created is when u can wiggle
  sema_up(&thread_item->startup_semaphore);
  // make room for arguments
  if_.esp = nxt_ptr - 12;

  // stack alignment
  while ((uint32_t)(if_.esp) % 16 != 12) {
    if_.esp--;
  }

  uint32_t** address_fun = pagedir_get_page(t->pcb->pagedir, if_.esp + 4);
  uint32_t** address_arg = pagedir_get_page(t->pcb->pagedir, if_.esp + 8);
  *address_fun = thread_item->tf;
  *address_arg = thread_item->arg;

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */

  remove_thread_reference(thread_item);
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid) {
  struct thread* t = thread_current();
  struct process* p = t->pcb;

  lock_acquire(&p->lock);
  for (struct list_elem* e = list_begin(&p->user_thread_list); e != list_end(&p->user_thread_list);
       e = list_next(e)) {
    struct user_thread_item* user_thread_item_here = list_entry(e, struct user_thread_item, elem);
    lock_acquire(&user_thread_item_here->lock);
    if (user_thread_item_here->tid == tid) {
      lock_release(&p->lock);

      if (user_thread_item_here->waited_on) {
        lock_release(&user_thread_item_here->lock);
        return TID_ERROR;
      }
      user_thread_item_here->waited_on = true;
      lock_release(&user_thread_item_here->lock);

      sema_down(&user_thread_item_here->semaphore);
      return tid;
    }
    lock_release(&user_thread_item_here->lock);
  }
  lock_release(&p->lock);
  return TID_ERROR;
}

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {
  struct thread* t = thread_current();
  struct user_thread_item* user_thread = t->user_thread_item_ptr;
  ASSERT(user_thread != NULL);

  pagedir_clear_page(t->pcb->pagedir, user_thread->user_vaddr_to_free);
  palloc_free_page(user_thread->kernel_page_to_free);

  sema_up(&user_thread->semaphore);
  thread_exit();
  NOT_REACHED();
}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {
  struct thread* t = thread_current();
  struct process* p = t->pcb;
  struct user_thread_item* user_thread = t->user_thread_item_ptr;

  if (user_thread != NULL) {
    sema_up(&user_thread->semaphore);
  }

  lock_acquire(&p->exit_lock);
  for (struct list_elem* e = list_begin(&p->user_thread_list); e != list_end(&p->user_thread_list);
       e = list_next(e)) {
    struct user_thread_item* user_thread_item_here = list_entry(e, struct user_thread_item, elem);
    if (user_thread_item_here->tid != t->tid) {
      lock_release(&p->exit_lock);
      tid_t ret = pthread_join(user_thread_item_here->tid);
      lock_acquire(&p->exit_lock);
    }
  }
  lock_release(&p->exit_lock);
  do_exit(0);
}