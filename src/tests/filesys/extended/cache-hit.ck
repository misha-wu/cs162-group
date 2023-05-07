# -*- perl -*-
use strict;
use warnings;
use tests::tests;
use tests::random;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(cache-hit) begin
(cache-hit) create "a"
(cache-hit) open "a"
(cache-hit) write "a"
(cache-hit) flush cache
(cache-hit) read "a"
(cache-hit) close "a"
(cache-hit) open "a"
(cache-hit) read "a"
(cache-hit) close "a"
(cache-hit) compare hit rates
(cache-hit) end
EOF
pass;
