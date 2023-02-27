# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF']);
(tell-good) begin
(tell-good) end
tell-good: exit(0)
EOF
pass;