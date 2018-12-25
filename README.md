# Hack The Box Little Tommy - Work in Progress

What I have built is a Pythonic process injector based on the C language's ptrace syscall. This is based on the following Python frameworks

1. python-ptrace
2. ctypes
3. cython

The following conclusions are derived from the Little Tommy exercise

1. The little_tommy application appears to have a double-free vulnerability
2. The goal of the process injector is to inject malicious code meant to trigger that double-free vulnerability and then dump the contents of the freed unallocated memory that still has a pointer pointing to it
# How it works

After running "python injector.py pid", the app automatically searches the memory map located at /proc/pid/maps. It then performs the math on the hexidecimal values to determine the maximum size of the buffer compared to your shellcode as well as pointing out important details such as executable locations in memory "r-xp".

At this point, you can press and select which section of memory you wish to attach and inject to.

After selecting your choice, the app will automatically make it's notes on the process's current activities, the contents of the RIP (64-bit instruction pointer), make a backup of the register's current state, and attempt to halt, attach, copy & backup, inject, reset, and reanimate the process for you.

So far it's been unsuccessful but I am very very close.

# It's probably easier to create a equivalent C program for this

The python-ptrace module missed a lot of important details that you will find out about the further you go into the module. For example, they failed to mention the syntax for attaching a process properly (noted in my code) and you require structs/classes to be able to properly transfer instructions from the CPU registers to backups.

# The generate_shellcode.sh script requires a reversal

The end-result of generate_shellcode.sh actually needs one more final step before it is ready to be put into the CPU instruction set. It needs to be reversed! The CPU registers operates in a LIFO manner of operation, or Last-In First-Out manner. So the instructions must be fed "backwards" into the CPU to get it to execute properly.

To do that, I created a Reverse function in injector.py that takes the existing non-reversed shellcode and saves it as a buffer, and reverses it into the correctly ordered shellcode.

# Contents

1. injector.py is the main process injector that will target any pid with the supplied buffer of unreversed shellcode (it auto reverses the string into the correct sequence for injection)

2. shellcode.c is the raw source code in C of what is being injected. As you can see, it simply attempts to double-free and then dump the contents of a dictionary of memory addresses

3. shellcode executable is the compiled version generated with gcc shellcode.c -o shellcode -m32 -march=i386

4. generate_shellcode.sh is the script I made to easily generate the Assembly opcodes in the unreversed shellcode while automatically eliminating null bytes
