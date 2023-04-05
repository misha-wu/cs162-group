# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(priority-cc5) begin
(priority-cc5) I am A, meow
(priority-cc5) I am D, meow
(priority-cc5) I am B, meow
(priority-cc5) I am C, meow
(priority-cc5) end
EOF
pass;
