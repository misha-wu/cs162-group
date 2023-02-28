# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(filesize-test) begin
(filesize-test) create filesize.txt
(filesize-test) equal
(filesize-test) bad fd
(filesize-test) end
filesize-test: exit(0)
EOF
pass;