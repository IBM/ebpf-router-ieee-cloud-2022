################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################


###########################################
## Ptrace do operation 
## leveraging python-ptrace for syscall interception
##
## * This must be called by only one tracer thread
## * syscall must be updated by the os architecture
## 
###########################################

from ptrace.debugger import PtraceDebugger
import ptrace.syscall
from ptrace.func_call import FunctionCallOptions

from ptrace.binding.cpu import CPU_SUB_REGISTERS

from ptrace.binding import (REGISTER_NAMES)

import sys
import signal
import ctypes
from ptrace.binding.func import (
        PTRACE_O_TRACEFORK, PTRACE_O_TRACEVFORK,
        PTRACE_O_TRACEEXEC, PTRACE_O_TRACESYSGOOD,
        PTRACE_O_TRACECLONE, THREAD_TRACE_FLAGS)


###########################################


MMAP_PROT_BITMASK = {k:v for v,k in ptrace.syscall.posix_arg.MMAP_PROT_BITMASK}
MMAP_PROT_BITMASK['PROT_ALL'] = MMAP_PROT_BITMASK['PROT_READ']\
                              | MMAP_PROT_BITMASK['PROT_WRITE']\
              | MMAP_PROT_BITMASK['PROT_EXEC']
MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20

syscalls =  dict()
for v, k in ptrace.syscall.linux.x86_64.SYSCALL_NAMES.items():
    if k not in syscalls:
        syscalls[k] = v

syscall_options = FunctionCallOptions(
            write_types=True,
            write_argname=True,
            write_address=True,
        )

iowait_calls = [syscalls[call] for call in ["epoll_wait", "select", "poll"]]
block_calls = [syscalls[call] for call in ["futex", "accept"]]
tabu_syscalls = [syscalls[call] for call in ["restart_syscall", "getsockopt", "setsockopt", "epoll_wait", "epoll_ctl", "sendmsg", "recvmsg", "rt_sigprocmask"]]
read_write_calls = [syscalls[call] for call in ["read", "readv", "write", "writev", "sendmsg", "recvmsg", "recvfrom", "sendto"]]


from signal import SIGTRAP
from ptrace.debugger import ProcessSignal


def is_attached(process):
    if process is None:
        return False
    return process.is_attached


def detach(process):
    debugger = process.debugger
    if is_attached(process):
        try:
            process.detach()
            debugger.deleteProcess(process)
            return True
        except ptrace.error.PtraceError as e:
            return False
    return True

def next_syscall_trap(process):
    # Trace until syscall enter
    process.syscall()
    process.debugger.waitSyscall(process=process)
    
    state = process.syscall_state
    syscall = state.event(syscall_options)
    rax = syscall.syscall
    regs = process.getregs()
    rdi = syscall.readArgumentValues(regs)[0]

    if rax in tabu_syscalls:
        return next_syscall_trap(process)
    
    if state.next_event == "exit":
        if rax in block_calls:
            return rax, rdi, None, None
        else:
            return next_syscall_trap(process)

    rip = process.getInstrPointer()
    rip = ctypes.c_long(rip).value
    return rax, rdi, regs, rip

def _next_syscall_trap(process):
    process.syscall()
    process.debugger.waitSyscall(process=process)
    state = process.syscall_state
    state.event(syscall_options)
    if state.next_event == "exit":
        _next_syscall_trap(process)

def run_asm(process, instr, old_rip):
    prev_rip = ctypes.c_long(old_rip - 2).value
    old_values = process.readBytes(prev_rip, len(instr))
    process.writeBytes(prev_rip, instr)
    process.setreg('rip', prev_rip)
    _next_syscall_trap(process)
    assert old_rip == process.getreg('rip'), "The instruction must be the same"
    process.writeBytes(prev_rip, old_values)
    result = process.getreg('rax')
    return result

def reserve_memory(process, size, old_regs, old_rip):
    regs = {'rax': syscalls['mmap'], 'rdi': 0, 'rsi': size,
            'rdx': MMAP_PROT_BITMASK['PROT_ALL'],
            'r10': MAP_PRIVATE | MAP_ANONYMOUS,
            'r8': -1, 'r9': 0}
    for reg, value in regs.items():
        process.setreg(reg, value)
    syscall_byte = str.encode(chr(0x0f) + chr(0x05))
    result = run_asm(process, syscall_byte, old_rip) # mmap. syscall
    process.setregs(old_regs)
    return ctypes.c_long(result).value

def free_memory(process, remote_addr, size, old_regs, old_rip):
    regs = {'rax': syscalls['munmap'], 'rdi': remote_addr, 'rsi': size,
            'rdx': 0,
            'r10': 0,
            'r8': 0, 'r9': 0}
    for reg, value in regs.items():
        process.setreg(reg, value)
    syscall_byte = str.encode(chr(0x0f) + chr(0x05))
    result = run_asm(process, syscall_byte, old_rip) # mmap. syscall
    process.setregs(old_regs)
    return result    


def read_memory(process, remote_addr, size):
    return process.readBytes(remote_addr, size)


def _get_name_value(name, value):
    if name in CPU_SUB_REGISTERS:
        full_name, shift, mask = CPU_SUB_REGISTERS[name]
        full_value = getattr(regs, full_name)
        full_value &= ~mask
        full_value |= ((value & mask) << shift)
        value = full_value
        name = full_name
        return name, value
    if name not in REGISTER_NAMES:
        return None, None
    else:
        return name, value
        
def call_syscall(process, call, rdi, rsi, rdx, r10, r8, r9, old_regs, old_rip):
    # set regs
    process.setreg('rax', syscalls[call])
    process.setreg('rdi', rdi)
    process.setreg('rsi', rsi)
    process.setreg('rdx', rdx)
    process.setreg('r10', r10)
    process.setreg('r8', r8)
    process.setreg('r9', r9)

    syscall_byte = str.encode(chr(0x0f) + chr(0x05))
    result = run_asm(process, syscall_byte, old_rip) # mmap. syscall
    process.setregs(old_regs)
    return result


def interpret(result, expect_type=None):
    if expect_type == "int":
        return int.from_bytes(result, byteorder=sys.byteorder)
    else:
        return result.decode("utf-8")


