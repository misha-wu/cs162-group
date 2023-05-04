/* Tests mkdir(). */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  CHECK(mkdir("a"), "mkdir \"a\"");
  CHECK(create("a/b", 512), "create \"a/b\"");
  CHECK(create("c", 512), "create \"c\"");
  CHECK(chdir("a"), "chdir \"a\"");
  CHECK(chdir(".."), "chdir \"..\"");
  open("c");
  // CHECK(open("c") > 1, "open \"c\"");
  // CHECK(open("b") > 1, "open \"b\"");
}
