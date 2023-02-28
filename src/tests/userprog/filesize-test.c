/* Tests filesize() */

#include "tests/lib.h"
#include "tests/main.h"


void
test_main(void)
{
    // should not error, filesize should be what we initialized it to be
    CHECK(create("filesize.txt", 5), "create filesize.txt");
    int fd = open ("filesize.txt");
    if (filesize(fd) == 5) {
        msg("equal");
    }

    // this should return -1 since 40 is a bad fd
    int bad = filesize(50);
    if (bad == -1) {
        msg("bad fd");
    }
}