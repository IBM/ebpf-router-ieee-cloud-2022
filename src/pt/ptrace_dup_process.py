################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

from static import ThreadState
import threading

import queue

from ptrace_do import read_memory, next_syscall_trap, is_attached, detach, read_write_calls
from ptrace_do import call_syscall, reserve_memory, free_memory
from static import is_traceable

import ptrace
from glibc import epoll_event
from ctypes import byref, memmove, c_char
from glibc import EPOLLIN

from static import getlogger
logger = getlogger(__name__)


class PtraceCommand():
    def __init__(self, func, args=None, ret=None):
        self.func = func
        self.args = args
        self.ret = ret
        self.complete = False


class PtraceDupProcess(threading.Thread):

    ATTACH=0
    DETACH=1
    NEXT_TRAP=2

    CALL_SYSCALL=10
    RESERVE_MEM=11
    FREE_MEM=12
    WRITE_BYTES=13
    READ_MEM=14

    # handle c struct
    EPOLL_EVENT_WRITE=15 

    ENTER_TRAP=20
    BLOCK_TRAP=21
    SLEEP_TRAP=22
    NONE_TRAP=23

    def __init__(self, tid, debugger, is_thread=True):
        threading.Thread.__init__(self)
        self.tid = tid
        self.debugger = debugger
        self.is_thread = is_thread

        self.state = ThreadState.PAUSE_STATE
        self.clear_value()

        ########## @control    ##########
        self.terminate = False

        self.command_queue = queue.Queue()

        logger.debug("New PtraceDupProcess {}".format(self.tid))

    def clear_value(self):
        ######### @ status ##############
        self.attached_process = None
        self.current_cmd = None
        self.trap_cmd = None
        self.attach_cmd = None
        self.read_write_fds = []
        self.rax = None
        self.rdi = None
        self.regs = None
        self.rip = None

###################################################################################################
##
## Command Processing
##
###################################################################################################
    def _process_detach(self):
        if self.trap_cmd is not None:
            self.trap_cmd.ret = PtraceDupProcess.NONE_TRAP
            self.trap_cmd.complete = True
        if self.attached_process is not None:
            self.current_cmd.ret = detach(self.attached_process)
            logger.debug("Process detach {0}: {1}".format(self.tid, self.current_cmd.ret))
            self.attach_cmd = None

    def _process_attach(self):
        self.attach_cmd = self.current_cmd
        if not is_attached(self.attached_process):
            try:
                if is_traceable(self.tid):
                    self.attached_process = self.debugger.addProcess(self.tid, False, is_thread=self.is_thread)
                    self.current_cmd.ret = True
                else:
                    logger.debug("{} cannot be traced".format(self.tid))
                    self.current_cmd.ret = False
            except (ptrace.error.PtraceError, ptrace.debugger.process_event.ProcessExit, ptrace.debugger.ptrace_signal.ProcessSignal) as e:
                logger.debug("{0} ptrace attach except {1}".format(self.tid, e))
                self.current_cmd.ret = False
                if self.attached_process is not None:
                    detach(self.attached_process)
        else:
            self.current_cmd.ret = True

        self.current_cmd.complete = True

    def _next_trap(self):
        self.trap_cmd = self.current_cmd

        if is_attached(self.attached_process):
            self.current_cmd.ret = PtraceDupProcess.SLEEP_TRAP
            self.current_cmd.complete = False
            self.rax, self.rdi, self.regs, self.rip = next_syscall_trap(self.attached_process)
            if self.rip is None:
                self.current_cmd.ret = PtraceDupProcess.BLOCK_TRAP
                if self.rax in read_write_calls and self.rdi not in self.read_write_fds:
                    self.read_write_fds.append(self.rdi)
                self.command_queue.put([self.current_cmd])
            else:
                self.current_cmd.ret = PtraceDupProcess.ENTER_TRAP
                if self.rax in read_write_calls and self.rdi not in self.read_write_fds:
                    self.read_write_fds.append(self.rdi)
                self.current_cmd.complete = True
            # logger.debug("Set rax,rdi = {0},{1}".format(self.rax, self.rdi))
        else:
            self.current_cmd.ret = PtraceDupProcess.NONE_TRAP # not attach
            logger.debug("Cannot trap next (process is not attached)")
        self.current_cmd.complete = True

    def _syscall(self, func):
        if not is_attached(self.attached_process):
            return

        args = self.current_cmd.args

        if func == PtraceDupProcess.CALL_SYSCALL:
            (call, rdi, rsi, rdx, r10, r8, r9) = args
            ret = call_syscall(self.attached_process, call, rdi, rsi, rdx, r10, r8, r9, self.regs, self.rip)
        elif func == PtraceDupProcess.EPOLL_EVENT_WRITE:
            (fd, remote_addr) = args
            ev = epoll_event()
            ev.events = EPOLLIN
            ev.data.fd = fd
            ev_buffer = (c_char*EPOLL_EVENT_SIZE)()
            memmove(ev_buffer, byref(ev), EPOLL_EVENT_SIZE)
            self.attached_process.writeBytes(remote_addr, ev_buffer)
            ret = True
        elif func == PtraceDupProcess.RESERVE_MEM:
            size = args
            ret = reserve_memory(self.attached_process, size, self.regs, self.rip)
        elif func == PtraceDupProcess.FREE_MEM:
            (remote_addr, size) = args
            ret = free_memory(self.attached_process, remote_addr, size, self.regs, self.rip)
        elif func == PtraceDupProcess.WRITE_BYTES:
            (remote_addr, buffer) = args
            self.attached_process.writeBytes(remote_addr, buffer)
            ret = True
        elif func == PtraceDupProcess.READ_MEM:
            (remote_addr, size) = args
            ret = read_memory(self.attached_process, remote_addr, size)    

        self.current_cmd.ret = ret

    def command_run(self, commands):
        for cmd in commands:
            self.current_cmd = cmd
            func = cmd.func
            if func == PtraceDupProcess.DETACH:
                self._process_detach()
                continue
            if func == PtraceDupProcess.ATTACH:
                self._process_attach()
            elif func == PtraceDupProcess.NEXT_TRAP:
                self._next_trap()
            else:
                self._syscall(func)
            self.current_cmd.complete = True

###################################################################################################

    def run(self):
        try:
            self.state = ThreadState.RUNNING_STATE
            while True:
                commands = self.command_queue.get()
                self.command_run(commands)
                self.command_queue.task_done()
                if self.terminate:
                    break
        except Exception as e:
            logger.warning("PtraceDup Error {0}: {1}".format(self.tid, e))
        finally:
            if not self.terminate:
                logger.debug("PtraceDup Detach at Finally {}".format(self.tid))
                cmd = PtraceCommand(PtraceDupProcess.DETACH)
                self.command_run([cmd])
            logger.debug("PtraceDup Finally {}".format(self.tid))
            self.state = ThreadState.DIE_STATE

###################################################################################################
##
##  controlled by duplicator
##
###################################################################################################


    def attach(self):
        if self.attached_process is not None:
            assert self.attach_cmd.ret, "The process must be already attached"
            return self.attach_cmd

        attach_cmd = PtraceCommand(PtraceDupProcess.ATTACH, ret=False)

        if self.died():
            return attach_cmd
        
        self.command_queue.put([attach_cmd])
        self.command_queue.join()
        if self.attach_cmd.ret:
            logger.debug("Process attach {}".format(self.tid))  
            self.next_try()
        return self.attach_cmd

    def detach(self):
        if self.died():
            return True

        if not self.is_attached():
            return True
        if self.state == ThreadState.DIE_STATE:
            logger.warning("PtraceDup {} unexpectedly died".format(self.tid))
            return True

        if self.sleeping_trap():
            return False

        cmd = PtraceCommand(PtraceDupProcess.DETACH)
        self.command_queue.put([cmd])
        self.command_queue.join()
        ret = self.current_cmd.ret
        if ret:
            logger.debug("Clear Value {}".format(self.tid))
            self.clear_value()
        return ret

    def next(self, calls):
        if self.died():
            return

        attach_check = self.is_attached()
        sleep_check = not self.sleeping_trap()
        assert attach_check and sleep_check, "Must not call on non-attaching or sleeeping tracer {0}: {1} (attach={2},sleep={3},qsize={4})".format(self.tid, [call[0] for call in calls], attach_check, sleep_check, self.command_queue.qsize())
        commands = [PtraceCommand(call[0], args=call[1]) for call in calls]
        self.command_queue.put(commands)
        self.command_queue.join()
        return self.current_cmd.ret # return result of last command

    def next_try(self):
        if self.sleeping_trap():
            return 

        if self.died():
            return

        if self.command_queue.qsize() == 0 and (self.trap_cmd is None or self.trap_cmd.complete):
            self.trap_cmd = PtraceCommand(PtraceDupProcess.NEXT_TRAP, ret=PtraceDupProcess.NONE_TRAP)
            self.command_queue.put([self.trap_cmd])

    def call_terminate(self):
        logger.debug("PtraceDup Individual Terminate {}".format(self.tid))
        self.terminate = True
        self.state = ThreadState.DIE_STATE
        cmd = PtraceCommand(PtraceDupProcess.DETACH)
        self.command_queue.put([cmd])

###################################################################################################
##
##  get status
##
###################################################################################################
    def died(self):
        if self.state == ThreadState.DIE_STATE:
            logger.warning("PtraceDup {} unexpectedly died".format(self.tid))
            return True
        return False

    def is_attached(self):
        if self.attached_process is not None:
            return self.attached_process.is_attached
        return False

    def rax(self):
        return self.rax
    
    def rdi(self):
        return self.rdi

    def get_read_write_fds(self):
        return self.read_write_fds

    def unknown_trap(self):
        if self.command_queue.qsize() > 0 or self.trap_cmd is None:
            return True # still unknown
        return False

    def sleeping_trap(self):
        if not self.is_attached():
            return False # not even be attached
        if self.trap_cmd is None:
            return False
        return not self.unknown_trap() and not self.trap_cmd.complete