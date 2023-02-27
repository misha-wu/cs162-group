/* Tests functionality of tell, including a good example and a bad example */

#include "tests/lib.h"

void test_main(void) {
  int w = tell(129320); //bad tell
  if (w != -1)
    fail("tell() returned %d", w);
}
