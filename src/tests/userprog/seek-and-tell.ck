
# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(seek-and-tell) begin
(seek-and-tell) create "dummy.txt"
(seek-and-tell) open "dummy.txt"
(seek-and-tell) tell "dummy.txt"
(seek-and-tell) seek "dummy.txt"
(seek-and-tell) tell "dummy.txt"
(seek-and-tell) end
seek-and-tell: exit(0)
EOF
pass;