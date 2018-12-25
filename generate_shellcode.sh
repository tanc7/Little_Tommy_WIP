#!/bin/bash

# warning, the results of this script generates shellcode that needs to be REVERSED before input into the CPU registers

purgenullbytes=$(objdump -d shellcode | tr "\t" " " | tr " " "\n" | egrep "^[0-9a-f]{2}$" | grep -v 00)

for i in $purgenullbytes:
	do echo -n "\x$i"
	done
