################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

import sys
import os
from ptrace_func import SocketFunction, CleanFunction, RWFunction, DuplicationFunction, AttachFunction, UtilityFunction
from static import ThreadState, ProcessCommand

from ptrace.debugger import PtraceDebugger

import pickle


from static import getlogger
logger = getlogger(__name__)

BUFFER_SIZE=4096

def stop_for_transfer(pid, process_dict, active_tids):
    detached_tid = 0
    if len(process_dict) > 0:
        found = False
        for tid in active_tids.copy():
            # some process tid is not attached
            if tid not in process_dict or process_dict[tid].state == ThreadState.DIE_STATE or not process_dict[tid].is_attached():
                detached_tid = tid
                found = True
                break
            # try detach one
            ret = CleanFunction.try_detach(process_dict, tid)
            if ret:
                found = True
                detached_tid = tid
                break
    else:
        detached_tid = pid
    return detached_tid

def process_dup_handler(pid, unix_sock):    
    process_dict = dict()
    cmd = None
    last_processing_tids = []
    debugger = PtraceDebugger()
    logger.info("New Handler for {}".format(pid))
    try:
        while True:
            req_data = unix_sock.recv(BUFFER_SIZE)
            try:
                (cmd, args) = pickle.loads(req_data)
            except:
                break
            if cmd == ProcessCommand.TRANSFER_DETACH:
                logger.debug("Stop for Transferring {}".format(pid))
                active_tids = args
                detached_tid = stop_for_transfer(pid, process_dict, active_tids)
                result = detached_tid
                logger.debug("Stop for Transferring {0} Completed {1}".format(pid, detached_tid))
            elif cmd == ProcessCommand.CLEAN_HOST_FD:
                (to_close_host_fd, active_tids)= args
                CleanFunction.clean_host_fd(process_dict, to_close_host_fd, active_tids)
                result = True
            elif cmd == ProcessCommand.UPDATE_PROCESSING_TIDS:
                active_tids = args
                last_processing_tids = AttachFunction.update_last_processing_tids(pid, debugger, process_dict, active_tids)
                result = last_processing_tids
            elif cmd == ProcessCommand.SET_TCP_NODELAY:
                (tid, fd, val) = args
                process = process_dict[tid]
                result = SocketFunction.get_and_set_tcp_nodelay(process, fd, val)
            elif cmd == ProcessCommand.SET_ANY_SOCKOPT:
                (tid, fd, level, optname, optval) = args
                process = process_dict[tid]
                result = SocketFunction.set_any_sockopt(process, fd, level, optname, optval)
            elif cmd == ProcessCommand.CHECK_RW:
                (active_tids, fd) = args
                reading = RWFunction.check_any_reading(process_dict, active_tids, fd)
                writing = RWFunction.check_any_writing(process_dict, active_tids, fd)
                result = (reading, writing)
            elif cmd == ProcessCommand.UPDATE_RWMEMO:
                read_write_memo = args
                RWFunction.update_read_write_memo(process_dict, read_write_memo)
                result = read_write_memo
            elif cmd == ProcessCommand.CONFIRM_SOCKET_ALIVE:
                (tid, overlay_inode, host_fd, fd) = args
                process = process_dict[tid]
                alive = SocketFunction.confirm_socket_alive(process, tid, overlay_inode, host_fd, fd)
                result = alive
            elif cmd == ProcessCommand.CHECK_RWBUFFER:
                (tid, fd) = args
                process = process_dict[tid]
                read_buffer = RWFunction.read_buffer(process, fd)
                write_buffer = RWFunction.write_buffer(process, fd)
                result = (read_buffer, write_buffer)
            elif cmd == ProcessCommand.AVAILABLE_TID:
                tid = UtilityFunction.get_available_tid(process_dict, last_processing_tids)
                result = tid
            elif cmd == ProcessCommand.EPOLL_DUP:
                (tid, fd, host_fd, nodelay) = args
                process = process_dict[tid]
                DuplicationFunction.epoll_dup(process, fd, host_fd)
                if nodelay >= 0:
                    SocketFunction.get_and_set_tcp_nodelay(process, fd, nodelay)
                result = True
            elif cmd == ProcessCommand.CURRENT_REGS:
                tid = args
                process = process_dict[tid]
                result = (process.rax, process.rdi)
            elif cmd == ProcessCommand.NEXT_TRAP:
                tid = args
                process = process_dict[tid]
                process.next_try()
                result = (process.rax, process.rdi)
            elif cmd == ProcessCommand.SHOW_PROCESS_STATUS:
                active_tids = args
                AttachFunction.show_process_status(process_dict, last_processing_tids, active_tids)
                result = True
            else:
                logger.warning("(pid={2}) Undefined command {0}({1})".format(cmd, args, pid))
            res_data = pickle.dumps(result)
            unix_sock.send(res_data)
    finally:
        CleanFunction.ptrace_clear(pid, process_dict, debugger)
        logger.info("(pid={0}) Handler Terminated".format(pid))
        unix_sock.send(b'END')
        unix_sock.close()

if __name__ == "__main__":
    import signal
    import socket

    pid = int(sys.argv[1])
    sockpath = sys.argv[2]
    unix_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    unix_sock.connect(sockpath)
    process_dup_handler(pid, unix_sock)


