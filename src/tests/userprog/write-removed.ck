# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(write-removed) begin
(write-removed) create sample2.txt
(write-removed) open "sample2.txt"
(write-removed) remove "sample2.txt"
(write-removed) write to "sample2.txt"
(write-removed) end
write-removed: exit(0)
EOF
pass;