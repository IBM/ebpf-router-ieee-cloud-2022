################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

from ptrace_do import interpret, syscalls
from ptrace_dup_process import PtraceDupProcess

import sys
from static import ProcessCommand, ThreadState

def get_inode(pid, fd):
    try:
        socket_link = os.readlink("/proc/{0}/fd/{1}".format(pid, fd))
        try:
            key, inode = socket_link[0:-1].split(":[")
            if key == "socket":
                return int(inode)
            else:
                return 0
        except:
            return 0
    except FileNotFoundError:
        return -1

from static import getlogger
logger = getlogger(__name__)

###################################################################################################
### syscall related dependency and variables
###################################################################################################

import socket
import termios
import fcntl
from glibc import EPOLL_CTL_DEL, EPOLL_CTL_ADD

import os

INT_SIZE = sys.getsizeof(int())
EPOLL_EVENT_SIZE = 12


###################################################################################################
### utility call
###################################################################################################
class UtilityFunction():

    def get_sockopt(process, fd):
        cmd = [(PtraceDupProcess.CALL_SYSCALL, ("fcntl", fd, fcntl.F_GETFL, 0, 0, 0, 0))]
        original_flags = process.next(calls=cmd)
        return original_flags

    def reserve_memory(process, size):
        cmd = [(PtraceDupProcess.RESERVE_MEM, size)]
        remote_addr = process.next(calls=cmd)
        return remote_addr

    def get_available_tid(process_dict, last_processing_tids):
        for tid in last_processing_tids:
            if process_dict[tid].trap_cmd is not None and process_dict[tid].trap_cmd.ret == PtraceDupProcess.ENTER_TRAP:
                return tid
        return None



###################################################################################################
## # connection call
##
## connection_closed: check specific fd
## inode_mismatch: in case of overwritten fd
## confirm_socket_alive: check connection close and inode mismatch
## get_tcp_nodelay/set_tcp_nodelay: get/set for tcp socket NODELAY option
## save_and_set_tcp_no_delay: call get_tcp_nodelay/set_tcp_nodelay according to to_set_nodelay list
##
###################################################################################################
import struct # for tcp no delay pack/unpack

class SocketFunction():

    def _connection_closed(process, tid, fd):
        result = UtilityFunction.get_sockopt(process, fd)
        if result >= 0:
            return False
        else:
            logger.warning("Socket closed {0},{1} ({2})".format(tid, fd, result))
            return True

    def _inode_mismatch(tid, fd, overlay_inode):
        current_inode = get_inode(tid, fd)
        if current_inode != overlay_inode:
            logger.warning("Inode mismatch {0},{1} {2}!={3}".format(tid, fd, overlay_inode, current_inode))
            return True
        return False
            
    def confirm_socket_alive(process, tid, overlay_inode, host_fd, fd):
        if SocketFunction._inode_mismatch(tid, fd, overlay_inode) or SocketFunction._connection_closed(process, tid, host_fd) or SocketFunction._connection_closed(process, tid, fd):
            return False
        return True
    

    def set_any_sockopt(process, fd, level, optname, optval):
        val_bytes = struct.pack('<i',optval)
        val_size = len(val_bytes)

        remote_addr = UtilityFunction.reserve_memory(process, val_size)
        cmd = [(PtraceDupProcess.WRITE_BYTES, (remote_addr, val_bytes))]
        process.next(calls=cmd)
        cmd = [(PtraceDupProcess.CALL_SYSCALL, ("setsockopt", fd, level, optname, remote_addr, val_size, 0))]
        set_ret = process.next(calls=cmd)
        logger.debug("Set Sockopt {0}-{1}={2} to {3}".format(level, optname, val_bytes, fd))
        return set_ret


    def _set_tcp_nodelay(process, fd, value, size):
        remote_addr = UtilityFunction.reserve_memory(process, size)
        cmd = [(PtraceDupProcess.WRITE_BYTES, (remote_addr, value))]
        process.next(calls=cmd)
        cmd = [(PtraceDupProcess.CALL_SYSCALL, ("setsockopt", fd, socket.IPPROTO_TCP, socket.TCP_NODELAY, remote_addr, size, 0))]
        set_ret = process.next(calls=cmd)
        logger.debug("Set TCP_NODELAY {0} to {1}".format(value, fd))
        return set_ret

    def _get_tcp_nodelay(process, fd, size):
        remote_addr = UtilityFunction.reserve_memory(process, size)
        cmd = [(PtraceDupProcess.CALL_SYSCALL, ("getsockopt", fd, socket.IPPROTO_TCP, socket.TCP_NODELAY, remote_addr, size, 0)), \
                (PtraceDupProcess.READ_MEM, (remote_addr, size))]
        result = process.next(calls=cmd)
        cmd = [(PtraceDupProcess.FREE_MEM, (remote_addr, size))]
        process.next(calls=cmd)
        logger.debug("Get TCP_NODELAY={}".format(struct.unpack('<i',result)))
        return result

    def get_and_set_tcp_nodelay(process, fd, val):
        val_bytes = struct.pack('<i',val)
        val_size = len(val_bytes)
        ret = SocketFunction._set_tcp_nodelay(process, fd, val_bytes, val_size)
        return ret
    

#################################f##################################################################
##  # Cleanning Part
##
##  try_detach: detach while keep tid dupthread alive if not sleep
##  try_force_detach: detach and terminate tid dupthread if not sleep
##  cancel: cancel specific fd (close server, client, close host fd)
##  clean_host_fd: run through to_close_host_fd --> get available tid to be attached and call close fd
##  clear: force detach all tid, clear server, clear client, quit debugger
##
###################################################################################################
class CleanFunction():

    def try_detach(process_dict, tid):
        if tid not in process_dict:
            return True
        sleeping = process_dict[tid].sleeping_trap()
        if sleeping:
            return False
        else:
            ret = process_dict[tid].detach()
            return ret


    def try_force_detach(process_dict, tid):
        if tid not in process_dict:
            return True
        sleeping = process_dict[tid].sleeping_trap()
        unknown = process_dict[tid].unknown_trap()
        if sleeping or unknown:
            return False
        else:
            process_dict[tid].call_terminate()
            process_dict[tid].join()
            del process_dict[tid]
            return True

    def clean_host_fd(process_dict, to_close_host_fd, active_tids):
        if len(to_close_host_fd) == 0:
            return

        available_tid = None
        for tid in active_tids.copy():
            ret = AttachFunction._try_or_attach_tid(debugger, process_dict, pid, tid)
            if ret:
                available_tid = tid
                break
        if available_tid is None:
            return

        logger.debug("To clean host fds: {0} for {1}".format(to_close_host_fd, available_tid))

        original_regs = process_dict[available_tid].regs
        original_rip = process_dict[available_tid].rip

        for host_fd in to_close_host_fd.copy():
            if not SocketFunction._connection_closed(process_dict[available_tid], available_tid, host_fd):
                cmd = [(PtraceDupProcess.CALL_SYSCALL, ("close", host_fd, 0, 0, 0, 0, 0))]
                process_dict[available_tid].next(calls=cmd)
            to_close_host_fd.remove(host_fd)


    def ptrace_clear(pid, process_dict, debugger):
        logger.debug("Ptrace clearing {}".format(pid))
        for tid in list(process_dict.keys()):
            CleanFunction.try_force_detach(process_dict, tid)
        try:
            debugger.quit()
        except:
            pass
        logger.debug("Ptrace properly cleared {}".format(pid))


###################################################################################################
## # Attachment Part
##
##  
##
###################################################################################################
class AttachFunction():

    def _try_or_attach_tid(debugger, process_dict, pid, tid):
        if tid not in process_dict or process_dict[tid].state == ThreadState.DIE_STATE:
            process = PtraceDupProcess(tid, debugger, is_thread=pid!=tid)
            process_dict[tid] = process
            process.start()
            attach_cmd = process.attach()
            if not attach_cmd.ret:
                logger.warning("Cannot attach {0} of {1}".format(tid, pid))
                return False
        else:
            process = process_dict[tid]

        if not process.is_attached():
            # detached somewhere else
            attach_cmd = process.attach()
            if not attach_cmd.ret:# fail to attach
                process_dict[tid].call_terminate()
                del process_dict[tid]
                logger.warning("Cannot attach {0} of {1}".format(tid, pid))
                return False

        if process.unknown_trap() or process.sleeping_trap(): # sleep or unknown
            return False

        trap_cmd = process.trap_cmd

        if trap_cmd.ret != PtraceDupProcess.ENTER_TRAP: # filter only enter trap
            if trap_cmd.ret == PtraceDupProcess.NONE_TRAP:
                process.next_try()
            return False

        assert process.command_queue.qsize() == 0 and process.trap_cmd.ret == PtraceDupProcess.ENTER_TRAP and process.trap_cmd.complete, "All conditions must be satisfied."

        return True

    def update_last_processing_tids(pid, debugger, process_dict, active_tids):
        last_processing_tids = []
        active_tids = active_tids.copy()
        while len(active_tids) > 0:
            tid = active_tids.pop()
            ret = AttachFunction._try_or_attach_tid(debugger, process_dict, pid, tid)
            if ret:
                last_processing_tids.append(tid)
            else:
                if tid in process_dict and not process_dict[tid].sleeping_trap():
                    active_tids.append(tid) # consider again if not known yet
        return last_processing_tids

    def show_process_status(process_dict, last_processing_tids, active_tids):
        processing = [(process_dict[tid].rax, process_dict[tid].rdi) for tid in last_processing_tids if tid in process_dict]
        sleeping = [(process_dict[tid].rax, process_dict[tid].rdi) for tid in process_dict if tid not in last_processing_tids]
        unknown = [tid for tid in active_tids if tid not in process_dict]
        logger.debug("Process status: processing={0}, sleeping={1}, unknown={2}".format(processing, sleeping, unknown))



###################################################################################################
### Read/Write Part
###################################################################################################
class RWFunction():

    def update_read_write_memo(process_dict, read_write_memo):
        for tid in process_dict:
            process = process_dict[tid]
            fd_list = process.get_read_write_fds()
            if len(fd_list) > 0:
                if tid not in read_write_memo:
                    read_write_memo[tid] = fd_list
                else:
                    if len(read_write_memo) == fd_list:
                        return
                    for fd in fd_list:
                        if fd not in read_write_memo[tid]:
                            read_write_memo[tid].append(fd)


    def write_buffer(process, fd):
        remote_addr = UtilityFunction.reserve_memory(process, INT_SIZE)
        cmd = [(PtraceDupProcess.CALL_SYSCALL, ("ioctl", fd, termios.TIOCOUTQ, remote_addr, 0, 0, 0)),\
                (PtraceDupProcess.READ_MEM, (remote_addr, INT_SIZE))]
        result = process.next(calls=cmd)
        cmd = [(PtraceDupProcess.FREE_MEM, (remote_addr, INT_SIZE))]
        process.next(calls=cmd)
        return interpret(result, expect_type="int")

    def read_buffer(process, fd):
        remote_addr = UtilityFunction.reserve_memory(process, INT_SIZE)
        cmd = [(PtraceDupProcess.CALL_SYSCALL, ("ioctl", fd, termios.FIONREAD, remote_addr, 0, 0, 0)),\
                (PtraceDupProcess.READ_MEM, (remote_addr, INT_SIZE))]
        result = process.next(calls=cmd)
        cmd = [(PtraceDupProcess.FREE_MEM, (remote_addr, INT_SIZE))]
        process.next(calls=cmd)
        return interpret(result, expect_type="int")

    def _check_writing_call(process, fd):
        rax = process.rax
        rdi = process.rdi
        if rax == syscalls["write"] or rax == syscalls["writev"] or rax == syscalls["sendto"]:
            if rdi == fd:
                return True
        return False

    def _check_reading_call(process, fd):
        rax = process.rax
        rdi = process.rdi
        if rax == syscalls["read"] or rax == syscalls["readv"] or rax == syscalls["recvfrom"]:
            if rdi == fd:
                return True
        return False

    def check_any_writing(process_dict, active_tids, fd):
        for tid in active_tids:
            if tid not in process_dict:
                continue
            is_write = RWFunction._check_writing_call(process_dict[tid], fd)
            if is_write:
                return tid
        return None

    def check_any_reading(process_dict, active_tids, fd):
        for tid in active_tids:
            if tid not in process_dict:
                continue
            is_read = RWFunction._check_reading_call(process_dict[tid], fd)
            if is_read:
                return tid
        return None

################################################################################################### 

###################################################################################################
### Duplication Part
###################################################################################################
class DuplicationFunction():

    def epoll_dup(process, fd, host_fd):
        epoll_fd = DuplicationFunction._epoll_del(process, fd)
        DuplicationFunction._dup(process, fd, host_fd)
        if epoll_fd > 0:
            DuplicationFunction._epoll_add(process, epoll_fd, fd)

    def _dup(process, fd, host_fd):
        original_flags = UtilityFunction.get_sockopt(process, fd)
        cmd = [(PtraceDupProcess.CALL_SYSCALL, ("fcntl", fd, fcntl.F_SETFL, original_flags & ~os.O_NONBLOCK, 0, 0, 0)), \
               (PtraceDupProcess.CALL_SYSCALL, ("fcntl", fd, fcntl.F_SETFL, original_flags & ~os.O_NONBLOCK, 0, 0, 0)), \
               (PtraceDupProcess.CALL_SYSCALL, ("dup2", host_fd, fd, 0, 0, 0, 0)), \
               (PtraceDupProcess.CALL_SYSCALL, ("close", host_fd, 0, 0, 0, 0, 0)), \
               (PtraceDupProcess.CALL_SYSCALL, ("fcntl", fd, fcntl.F_SETFL, original_flags,0, 0, 0))]
        process.next(calls=cmd)
        after_sock_opt = UtilityFunction.get_sockopt(process, fd)
        logger.info("Dup2 {0},{1} when ({2}, {3}) with opt={4}".format(process.tid, fd, process.rax, process.rdi, after_sock_opt))

    def _epoll_del(process, target_fd):
        fd_path = "/proc/{}/fd".format(process.tid)
        try:
            fds = os.listdir(fd_path)
            for fd in fds:
                name = os.readlink("{0}/{1}".format(fd_path, fd))
                if "eventpoll" in name:
                    epoll_fd = int(fd)
                    
                    cmd = [(PtraceDupProcess.CALL_SYSCALL, ("epoll_ctl", epoll_fd, EPOLL_CTL_DEL, target_fd, 0, 0, 0))]
                    result = process.next(calls=cmd)
                    if result == 0:
                        return epoll_fd
        except FileNotFoundError:
            logger.warning("Epoll delete not found {}".format(fd_path))
            return -1
        return -1

    def _epoll_add(process, epoll_fd, fd):
        logger.debug("Epoll update {0},{1} on {2}".format(process.tid, fd, epoll_fd))
        remote_addr = UtilityFunction.reserve_memory(process, EPOLL_EVENT_SIZE)
        cmd = [(PtraceDupProcess.EPOLL_EVENT_WRITE, (fd, remote_addr)), \
                (PtraceDupProcess.CALL_SYSCALL, ("epoll_ctl", epoll_fd, EPOLL_CTL_ADD, fd, remote_addr, 0, 0))]
        result = process.next(calls=cmd)
        cmd = [(PtraceDupProcess.FREE_MEM, (remote_addr, EPOLL_EVENT_SIZE))]
        process.next(calls=cmd)
        return result

###################################################################################################