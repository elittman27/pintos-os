# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(wait-grchild) begin
(process-b) run
(process-c) run
process-c: exit(12)
(process-b) Check that expected pid for process-c equals its actual pid
process-b: exit(11)
(wait-grchild) wait(child) = 11
(wait-grchild) wait(grandchild) = -1
(wait-grchild) end
wait-grchild: exit(0)
EOF
pass;

