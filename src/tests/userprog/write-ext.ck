# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(write-ext) begin
(write-ext) create sample2.txt
(write-ext) open "sample2.txt"
(write-ext) write to "sample2.txt"
(write-ext) end
write-ext: exit(0)
EOF
pass;