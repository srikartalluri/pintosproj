# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(new-test) begin
(new-test) PASS
(new-test) end
EOF
pass;
