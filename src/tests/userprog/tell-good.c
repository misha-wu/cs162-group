/* Tests functionality of tell, including a good example and a bad example */

#include "tests/lib.h"

void test_main(void) {
  int h1 = open("sample.txt");

  int w = tell(h1); //good tell
  if(w == -1) {
    fail("should have been valid");
  }
}
