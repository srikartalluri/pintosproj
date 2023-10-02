#include "userprog/process.h"
#include "list.h"

int init_sharing(child_node* shared_data) {
  int err = 0;
  shared_data = malloc(sizeof(child_node));
  if (shared_data == NULL)
    return -1;
  sema_init(&(shared_data->sema), 0);

  //err = pthread_mutex_init ( &(shared_data->lock), NULL);
  if (err != 0) {
    return err;
  }
  shared_data->ref_cnt = 2;
  shared_data->err_code = 0;
  return err;
}

void set_tid(pid_t tid, child_node* shared_data) { shared_data->pid = tid; }

int downupkid(pid_t id, struct list list, bool down) {
  typedef struct list_elem list_elem;
  list_elem* e;
  for (e = list_begin(&list); e != list_end(&list); e = list_prev(e)) {
    child_node* f = list_entry(e, struct child_node, elem);
    if (f->pid == id) {
      if (down)
        sema_down(&(f->sema));
      else
        sema_up(&(f->sema));
      return 0;
    }
  }
  return -1;
}

child_node* getkid(pid_t tid, struct list list) {
  if (list_empty(&list)) {
    return NULL;
  }
  typedef struct list_elem list_elem;
  list_elem* e;
  for (e = list_begin(&list); e != list_end(&list); e = list_prev(e)) {
    child_node* f = list_entry(e, struct child_node, elem);
    if (f->pid == tid)
      return f;
  }
  return NULL;
}
