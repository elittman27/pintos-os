# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF']);
(join-locks) begin
(join-locks) Main starting
(join-locks) Starting thread T1
(join-locks) Acquired lock in T1.
(join-locks) Starting thread T2
(join-locks) Acquiring lock in T2.
(join-locks) Calling join from T1 on T2 should've released the lock.
(join-locks) Acquired lock in T2.
(join-locks) Finishing thread T2
(join-locks) Main acquired lock released by T2
(join-locks) Finishing thread T1
(join-locks) Main finishing
(join-locks) end
join-locks: exit(0)
EOF
pass;