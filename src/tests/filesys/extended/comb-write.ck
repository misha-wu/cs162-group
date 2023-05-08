# -*- perl -*-
use strict;
use warnings;
use tests::tests;
use tests::random;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(comb-write) begin
(comb-write) create "a"
(comb-write) open "a"
(comb-write) write "a"
(comb-write) compare device stats
(comb-write) compare correctness
(comb-write) verified contents of "a"
(comb-write) end
EOF
pass;
