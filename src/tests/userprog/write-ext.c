#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"
#include "sample.inc"
#include <string.h>

void test_main(void) {
  int handle;
  int byte_cnt;
  bool err;
  CHECK(create("sample2.txt", (sizeof sample) >> 1), "create sample2.txt");
  CHECK((handle = open("sample2.txt")) > 1, "open \"sample2.txt\"");
  byte_cnt = write(handle, sample, sizeof sample - 1);
  msg("write to \"sample2.txt\"");
  if (filesize(handle) != (sizeof sample) >> 1)
    fail("extended filesize");
  close(handle);
}