################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

class SyncState():
    UNKNOWN_STATE = 0
    ZERO_READ_ZERO_WRITE = 1
    ZERO_READ = 2
    ZERO_WRITE = 3
    READ_WRITE = 4
    REVOKED_STATE = -1

    def string(state):
        if state == SyncState.UNKNOWN_STATE:
            return "UNKNOWN"
        elif state == SyncState.ZERO_READ_ZERO_WRITE:
            return "ZERO"
        elif state == SyncState.ZERO_READ:
            return "ZERO_READ"
        elif state == SyncState.ZERO_WRITE:
            return "ZERO_WRITE"
        elif state == SyncState.READ_WRITE:
            return "READ_WRITE"
        return "UNREGISTERED {}".format(state)

    def __init__(self, fd):
        self.state = SyncState.UNKNOWN_STATE
        self.fd = fd
    
    def set_state(self, read_buffer, write_buffer):
        if read_buffer == 0:
            if write_buffer == 0:
                self.state = SyncState.ZERO_READ_ZERO_WRITE
            else:
                self.state = SyncState.ZERO_READ
        else:
            if write_buffer == 0:
                self.state = SyncState.ZERO_WRITE
            else:
                self.state = SyncState.READ_WRITE

    def clear(self):
        self.state = SyncState.UNKNOWN_STATE

class ServerState():
    REVOKED=-1
    SYNC=0
    CONFIRMED=1
    DONE=2
    
class ClientState():
    REVOKED=-1
    INIT_STATE=0
    WRITING=1
    NOT_WRITING=2
    WAIT_CONFIRM=3
    DONE=4
    WAIT_SERVER=5
    
    def string(state):
        if state == ClientState.INIT_STATE:
            return "INIT"
        elif state == ClientState.WRITING:
            return "WRITING"
        elif state == ClientState.NOT_WRITING:
            return "NOT WRITING"
        return "UNREGISTERED {}".format(state)

class ThreadState():

    PAUSE_STATE=0
    RUNNING_STATE=1
    BLOCKING_STATE=2
    PROCESSING_STATE=3
    DIE_STATE=4

class ProcessCommand():

    TRANSFER_DETACH = 1
    CLEAN_HOST_FD = 2
    UPDATE_PROCESSING_TIDS = 3
    SET_TCP_NODELAY = 4
    CHECK_RW = 5
    UPDATE_RWMEMO = 6
    CONFIRM_SOCKET_ALIVE = 7
    CHECK_RWBUFFER = 8
    AVAILABLE_TID = 9
    EPOLL_DUP = 10
    CURRENT_REGS = 11
    NEXT_TRAP = 12
    SHOW_PROCESS_STATUS = 13

    SET_ANY_SOCKOPT=15

    TERMINATE = -1



###################################################################################################
### process-related general call
###################################################################################################
import os


def get_all_tids(pid):
    task_folder = "/proc/{}/task".format(pid)
    if os.path.exists(task_folder):
        tids = [int(tid) for tid in os.listdir(task_folder)]
        return tids
    return []

def is_traceable(pid):
     status_file = "/proc/{}/status".format(pid)
     if not os.path.exists(status_file):
         return False
     with open(status_file, "r") as f:
         while True:
            line = f.readline()
            if not line:
                break
            if "TracerPid" in line:
                tracer_pid = line.strip("\n").split(":")[-1].strip()
                if tracer_pid == "0":
                    return True
                else:
                    return False
     return False


def tracer(pid):
     status_file = "/proc/{}/status".format(pid)
     if not os.path.exists(status_file):
         return False
     with open(status_file, "r") as f:
         while True:
            line = f.readline()
            if not line:
                break
            if "TracerPid" in line:
                tracer_pid = line.strip("\n").split(":")[-1].strip()
                return tracer_pid
     return -1



def process_died(tid):
    stat_path = "/proc/{}/stat".format(tid)
    if not os.path.exists(stat_path):
        return True
    with open(stat_path, "r") as f:
        line = f.read()
    status = line.split(" ")[2].lower()
    if status == 'z':
        return True
    return False
###################################################################################################

def pidfd_str(overlay_pid_fd):
    return str(overlay_pid_fd)

def pidfd_val(overlay_pid_fd_str):
    splits = overlay_pid_fd_str[1:-1].split(",")
    return (int(splits[0]), int(splits[1]))

###################################################################################################


class TracerRequest():
    cmd = None
    args = None

class TracerResponse():
    result = None


###################################################################################################
#### Logging 
###################################################################################################
import logging
import os
import sys

def getlogger(identifier):
    formatter = logging.Formatter(fmt='%(filename)s\t%(asctime)s %(levelname)-8s %(message)s',
                                    datefmt='%Y-%m-%d %H:%M:%S')
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)

    logger = logging.getLogger(identifier)
    logger.propagate = False
    logger.addHandler(handler)

    if "ROUTER_LOGLEVEL" not in os.environ:
        os.environ["ROUTER_LOGLEVEL"] = "WARNING"
    logger.setLevel(getattr(logging, os.environ["ROUTER_LOGLEVEL"]))
    return logger

###################################################################################################
