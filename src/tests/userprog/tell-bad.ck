# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF']);
(tell-bad) begin
(tell-bad) end
tell-bad: exit(0)
EOF
pass;