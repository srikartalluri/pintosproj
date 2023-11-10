/* The root process spawns a thread and waits until it starts running.
   The thread waits on root main, which exec's another process.
   We want to test that the exec'd process only has one main thread of
   control, and not a "copy" of the child thread created above.
   We do this by having the exec'd process pthread_exit() to wait on
   all other threads. Nothing should be printed except the exit code.
   Then, both root and the child thread finish when root main calls pthread_exit() */

#include "tests/lib.h"
#include <string.h>
#include <syscall.h>
#include <pthread.h>

// Global variables
sema_t hang_main;

void thread_function(void* arg_);


int main(int argc, char* argv[]) {
  test_name = "join-dif-proc";
//   if (argc != 2)
//     fail("Incorrect usage");

  if (!strcmp(argv[1], "root")){
    msg("Root Process Starting");
    pid_t ret = (pid_t)exec("join-dif-proc child");

    if(ret == -1){
        fail("exec failed");
    }

    // should fail
    pthread_check_join(ret);


    fail("reached unreachable statement");



  }

  if (!strcmp(argv[1], "child")){

    msg("Printed from child process");



  }

}