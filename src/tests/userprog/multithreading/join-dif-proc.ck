# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF', <<'EOF', <<'EOF']);
(join-dif-proc) Root Process Starting
(join-dif-proc) Printed from child process
join-dif-proc: exit(0)
join-dif-proc: exit(1)
EOF
(join-dif-proc) Root Process Starting
(join-dif-proc) Printed from child process
join-dif-proc: exit(1)
join-dif-proc: exit(0)
EOF
(join-dif-proc) Root Process Starting
join-dif-proc: exit(1)
(join-dif-proc) Printed from child process
join-dif-proc: exit(0)
EOF
pass;