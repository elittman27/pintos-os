
# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(across-files) begin
(across-files) create "dummy"
(across-files) open "dummy"
(across-files) open "dummy"
(across-files) tell "dummy" comparison
(across-files) tell "dummy" comparison
(across-files) seek "dummy"
(across-files) tell "dummy" comparison
(across-files) tell "dummy"
(across-files) end
across-files: exit(0)
EOF
pass;