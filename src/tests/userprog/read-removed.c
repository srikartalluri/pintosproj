/*this test checks whther a process is able to write to a file thatit opened but removed without closing*/
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"
#include <string.h>

void test_main(void) {
  char* the_str = "time to start hw3";
  char* buffer[50];
  int handle;
  int byte_cnt;
  int err;
  CHECK((handle = open("sample2.txt")) > 1, "open \"sample2.txt\"");
  CHECK((err = remove("sample2.txt")) == 0, "remove \"sample2.txt\"");
  byte_cnt = write(handle, the_str, sizeof the_str - 1);
  if (byte_cnt != sizeof the_str - 1)
    fail("write() returned %d instead of %zu", byte_cnt, sizeof the_str - 1);
  msg("write to \"sample2.txt\"");
  read(handle, buffer, 50);
  if (strcmp(buffer, the_str) != 0)
    fail("did not write correctly to the ghost file");
  close(handle);
}