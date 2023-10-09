# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(read-removed) begin
(read-removed) open "sample2.txt"
(read-removed) remove "sample2.txt"
(read-removed) write to "sample2.txt"
read-removed : exit(0)
EOF
pass;