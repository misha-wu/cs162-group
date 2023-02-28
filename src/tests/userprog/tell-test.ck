# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF']);
(tell-test) begin
(tell-test) end
tell-test: exit(0)
EOF
pass;